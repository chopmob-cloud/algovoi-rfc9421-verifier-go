package ecdsa

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
	"testing"
)

func rawSig(r, s *big.Int, fieldSize int) []byte {
	out := make([]byte, 2*fieldSize)
	r.FillBytes(out[:fieldSize])
	s.FillBytes(out[fieldSize:])
	return out
}

type curveCase struct {
	name      string
	curve     elliptic.Curve
	newHash   func() hash.Hash
	verify    verifierFunc
	fieldSize int
}

func cases() []curveCase {
	return []curveCase{
		{"P-256", elliptic.P256(), sha256.New, VerifyP256, 32},
		{"P-384", elliptic.P384(), sha512.New384, VerifyP384, 48},
	}
}

func TestECDSAValidAndTampered(t *testing.T) {
	const signingBase = "\"@method\": POST\n\"@path\": /pay"

	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := stdecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			h := tc.newHash()
			h.Write([]byte(signingBase))
			digest := h.Sum(nil)
			r, s, err := stdecdsa.Sign(rand.Reader, priv, digest)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			sig := rawSig(r, s, tc.fieldSize)
			pubBytes := elliptic.Marshal(tc.curve, priv.X, priv.Y) //nolint:staticcheck // SEC1 uncompressed encode

			// Valid signature verifies.
			ok, verr := tc.verify(signingBase, sig, pubBytes)
			if verr != nil {
				t.Fatalf("valid case errored: %v", verr)
			}
			if !ok {
				t.Fatal("valid signature did not verify")
			}

			// Hex public key also accepted.
			okHex, verr := tc.verify(signingBase, sig, hexEncode(pubBytes))
			if verr != nil || !okHex {
				t.Fatalf("hex public key: ok=%v err=%v", okHex, verr)
			}

			// Tampered signature (flip one bit of s) does not verify.
			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)-1] ^= 0x01
			ok, verr = tc.verify(signingBase, tampered, pubBytes)
			if verr != nil {
				t.Fatalf("tampered sig errored unexpectedly: %v", verr)
			}
			if ok {
				t.Fatal("tampered signature verified (should not)")
			}

			// Tampered message (different signing base) does not verify.
			ok, verr = tc.verify(signingBase+"X", sig, pubBytes)
			if verr != nil {
				t.Fatalf("tampered message errored unexpectedly: %v", verr)
			}
			if ok {
				t.Fatal("signature verified against a different message (should not)")
			}

			// Wrong signature length is a setup error, not a false result.
			if _, verr = tc.verify(signingBase, sig[:len(sig)-1], pubBytes); verr == nil {
				t.Fatal("expected error on wrong signature length")
			}

			// r = 0 is rejected as an out-of-range value (false, no error).
			zeroR := rawSig(big.NewInt(0), s, tc.fieldSize)
			ok, verr = tc.verify(signingBase, zeroR, pubBytes)
			if verr != nil || ok {
				t.Fatalf("r=0 should be false/no-error, got ok=%v err=%v", ok, verr)
			}

			// An off-curve / malformed public key is a setup error.
			bad := append([]byte(nil), pubBytes...)
			bad[len(bad)-1] ^= 0xFF
			if _, verr = tc.verify(signingBase, sig, bad); verr == nil {
				t.Fatal("expected error on off-curve public key")
			}
		})
	}
}

func TestStrictLowS(t *testing.T) {
	const signingBase = "canonical-low-s-test"
	tc := cases()[0] // P-256
	priv, err := stdecdsa.GenerateKey(tc.curve, rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	order := tc.curve.Params().N
	halfOrder := new(big.Int).Rsh(order, 1)

	// Find a signature and, if needed, flip s to its high-s equivalent (n - s),
	// which is still a valid ECDSA signature but non-canonical.
	h := sha256.New()
	h.Write([]byte(signingBase))
	digest := h.Sum(nil)
	r, s, err := stdecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if s.Cmp(halfOrder) <= 0 {
		s = new(big.Int).Sub(order, s) // make it high-s
	}
	sig := rawSig(r, s, tc.fieldSize)
	pubBytes := elliptic.Marshal(tc.curve, priv.X, priv.Y) //nolint:staticcheck

	// Default (strict off): high-s still verifies.
	SetStrictLowS(false)
	ok, verr := tc.verify(signingBase, sig, pubBytes)
	if verr != nil || !ok {
		t.Fatalf("high-s with strict off should verify: ok=%v err=%v", ok, verr)
	}

	// Strict on: high-s is rejected.
	SetStrictLowS(true)
	defer SetStrictLowS(false)
	ok, verr = tc.verify(signingBase, sig, pubBytes)
	if verr != nil {
		t.Fatalf("strict low-s errored: %v", verr)
	}
	if ok {
		t.Fatal("high-s signature verified under strict low-s (should not)")
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i] = hexdigits[c>>4]
		out[2*i+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
