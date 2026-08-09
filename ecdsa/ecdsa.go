// Package ecdsa is the SEPARATE ECDSA add-on for the AlgoVoi RFC 9421 verifier.
//
// It provides the two RFC 9421-registered ECDSA algorithms:
//
//	ecdsa-p256-sha256 (RFC 9421 3.3.5): P-256, SHA-256, 64-byte r||s signature
//	ecdsa-p384-sha384 (RFC 9421 3.3.6): P-384, SHA-384, 96-byte r||s signature
//
// RFC 9421 carries the signature as the raw big-endian concatenation r||s (each
// component field-element-sized), NOT DER. Public keys are supplied out of band as
// SEC1 point bytes (compressed or uncompressed) or hex.
//
// This is a pure add-on: it imports the core verifier package (for the shared
// VerifyError family) and the Go standard library only. The core package never
// imports this package, mirroring the Python / TypeScript "pure add-on"
// architecture where the ECDSA provider depends on the core verifier and not the
// other way around.
//
// Hardening applied before accepting a signature:
//   - the public-key point must be on the curve and not the identity;
//   - the signature length must match the curve exactly (64 / 96 bytes);
//   - r and s must each be in [1, n-1] (reject zero / out-of-range);
//   - optional low-s (canonical) enforcement to defeat signature malleability,
//     controlled by SetStrictLowS (default off, for spec interop).
package ecdsa

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
	"strings"
	"sync/atomic"

	"github.com/chopmob-cloud/algovoi-rfc9421-verifier-go/verifier"
)

// ECDSAError is raised on an ECDSA setup error (bad key or signature shape). It
// embeds the core *verifier.VerifyError, so it is part of the same error family as
// the core setup errors (mirroring the reference where ECDSAError extends
// VerifyError).
type ECDSAError struct {
	*verifier.VerifyError
}

func newECDSAError(format string, a ...interface{}) *ECDSAError {
	return &ECDSAError{verifier.NewVerifyError(format, a...)}
}

// strictLowS toggles canonical low-s enforcement. Off by default: standard ECDSA
// signers may emit high-s and stay RFC 9421 compliant. Turn on for deployments
// that require a single canonical signature.
var strictLowS atomic.Bool

// SetStrictLowS enables or disables canonical low-s enforcement (anti-malleability).
func SetStrictLowS(enabled bool) { strictLowS.Store(enabled) }

// coercePubKey parses SEC1 point bytes (compressed 0x02/0x03 or uncompressed 0x04)
// or a hex string into an on-curve public key. It returns an *ECDSAError for an
// invalid or off-curve point.
func coercePubKey(publicKey interface{}, curve elliptic.Curve) (*stdecdsa.PublicKey, error) {
	var data []byte
	switch pk := publicKey.(type) {
	case string:
		raw := strings.TrimPrefix(pk, "0x")
		if len(raw)%2 != 0 || !isHex(raw) {
			return nil, newECDSAError("public_key hex is invalid")
		}
		data = hexDecode(raw)
	case []byte:
		data = pk
	default:
		return nil, newECDSAError("public_key must be SEC1 point bytes or hex, got %T", publicKey)
	}
	if len(data) == 0 {
		return nil, newECDSAError("public_key is empty")
	}

	var x, y *big.Int
	switch data[0] {
	case 0x04:
		x, y = elliptic.Unmarshal(curve, data) //nolint:staticcheck // stdlib SEC1 uncompressed decode
	case 0x02, 0x03:
		x, y = elliptic.UnmarshalCompressed(curve, data)
	default:
		return nil, newECDSAError("public_key has unknown SEC1 point prefix 0x%02x", data[0])
	}
	if x == nil || y == nil {
		return nil, newECDSAError("public_key is not a valid point on %s", curve.Params().Name)
	}
	return &stdecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

type verifierFunc func(signingBase string, signatureBytes []byte, publicKey interface{}) (bool, error)

func makeVerifier(curve elliptic.Curve, newHash func() hash.Hash) verifierFunc {
	fieldSize := (curve.Params().BitSize + 7) / 8
	order := curve.Params().N
	halfOrder := new(big.Int).Rsh(order, 1)

	return func(signingBase string, signatureBytes []byte, publicKey interface{}) (bool, error) {
		if len(signatureBytes) != 2*fieldSize {
			return false, newECDSAError("%s signature must be %d bytes (r||s), got %d",
				curve.Params().Name, 2*fieldSize, len(signatureBytes))
		}
		r := new(big.Int).SetBytes(signatureBytes[:fieldSize])
		s := new(big.Int).SetBytes(signatureBytes[fieldSize:])
		// r, s must be in [1, n-1]; reject zero and out-of-range.
		if r.Sign() <= 0 || r.Cmp(order) >= 0 || s.Sign() <= 0 || s.Cmp(order) >= 0 {
			return false, nil
		}
		if strictLowS.Load() && s.Cmp(halfOrder) > 0 {
			return false, nil
		}
		pub, err := coercePubKey(publicKey, curve)
		if err != nil {
			return false, err
		}
		h := newHash()
		h.Write([]byte(signingBase))
		digest := h.Sum(nil)
		return stdecdsa.Verify(pub, digest, r, s), nil
	}
}

// VerifyP256 verifies an ecdsa-p256-sha256 signature (raw 64-byte r||s).
var VerifyP256 = makeVerifier(elliptic.P256(), sha256.New)

// VerifyP384 verifies an ecdsa-p384-sha384 signature (raw 96-byte r||s).
var VerifyP384 = makeVerifier(elliptic.P384(), sha512.New384)

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hexDecode(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		out[i] = hexVal(s[2*i])<<4 | hexVal(s[2*i+1])
	}
	return out
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
