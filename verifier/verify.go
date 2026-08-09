package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// VerifyError is returned when verification setup is invalid (not when a signature
// merely fails to verify, which is reported as a false result / a VerifyResult
// error entry). The ecdsa add-on package builds its ECDSAError on top of this type,
// mirroring the reference where ECDSAError extends VerifyError.
type VerifyError struct{ Msg string }

func (e *VerifyError) Error() string { return e.Msg }

// NewVerifyError constructs a *VerifyError. Exported so add-on packages (ecdsa)
// can raise setup errors of the same family as the core.
func NewVerifyError(format string, a ...interface{}) *VerifyError {
	return &VerifyError{Msg: fmt.Sprintf(format, a...)}
}

// PublicKeyBytes coerces raw 32-byte Ed25519 key bytes or a hex string (with or
// without a 0x prefix) to 32 key bytes.
func PublicKeyBytes(publicKey interface{}) ([]byte, error) {
	switch pk := publicKey.(type) {
	case []byte:
		if len(pk) != 32 {
			return nil, NewVerifyError("Ed25519 public key must be 32 bytes, got %d", len(pk))
		}
		return pk, nil
	case string:
		keyHex := strings.TrimPrefix(pk, "0x")
		kb, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, NewVerifyError("public key hex is invalid: %v", err)
		}
		if len(kb) != 32 {
			return nil, NewVerifyError("Ed25519 public key hex must decode to 32 bytes, got %d", len(kb))
		}
		return kb, nil
	default:
		return nil, NewVerifyError("public_key must be bytes or hex str, got %T", publicKey)
	}
}

// VerifySignature verifies an Ed25519 signature over the signing base.
//
// It returns (true, nil) on success and (false, nil) on a signature mismatch. It
// returns a non-nil error only for invalid inputs (bad algorithm, wrong key or
// signature length, or a public key rejected by the trust-boundary gate).
//
// The public-key gate runs BEFORE verification: non-canonical, off-curve, and
// small-order keys are rejected, since Go's ed25519.Verify (like libsodium's basic
// verify) does not reject small-order keys on its own.
func VerifySignature(signingBase string, signatureBytes []byte, publicKey interface{}, algorithm string) (bool, error) {
	if strings.ToLower(algorithm) != "ed25519" {
		return false, NewVerifyError("this core package supports ed25519 only; got %q", algorithm)
	}
	if len(signatureBytes) != 64 {
		return false, NewVerifyError("Ed25519 signature must be 64 bytes, got %d", len(signatureBytes))
	}
	pkBytes, err := PublicKeyBytes(publicKey)
	if err != nil {
		return false, err
	}
	if err := CheckEd25519PublicKey(pkBytes); err != nil {
		return false, NewVerifyError("%s", err.Error())
	}
	ok := ed25519.Verify(ed25519.PublicKey(pkBytes), []byte(signingBase), signatureBytes)
	return ok, nil
}

// NonceSeen is an optional caller-supplied store probe: it answers whether the
// (nonce, keyid) pair has already been used. It is only ever called with an
// authentic message (after the signature verifies). A store failure must fail
// closed by returning an error.
type NonceSeen func(nonce, keyid string) (bool, error)

// VerifyRequestOptions carries the policy inputs for VerifyRequest.
type VerifyRequestOptions struct {
	Scheme               string
	RequireContentDigest bool
	RequireAlgorithm     string
	Mode                 string
	Now                  *int64
	MaxAgeSeconds        *int64
	MaxSkewSeconds       int64
	EnforceExpires       bool
	RequireCreated       bool
	ExpectedTag          string
	HasExpectedTag       bool
	RequireTag           bool
	AllowedAlgorithms    map[string]bool
	NonceSeen            NonceSeen
}

// DefaultVerifyRequestOptions returns options matching the reference defaults:
// RFC 9421 mode, content-digest required, Ed25519 the only allowed algorithm,
// expires enforced, 60s skew.
func DefaultVerifyRequestOptions() VerifyRequestOptions {
	return VerifyRequestOptions{
		Scheme:               "https",
		RequireContentDigest: true,
		Mode:                 ModeRFC9421,
		MaxSkewSeconds:       60,
		EnforceExpires:       true,
		AllowedAlgorithms:    map[string]bool{"ed25519": true},
	}
}

// VerifyResult is the outcome of an RFC 9421 verification. Valid is true only if
// every check ran and every check passed.
type VerifyResult struct {
	Valid              bool
	SignatureValid     bool
	ContentDigestValid bool
	SigningBase        string
	CoveredComponents  []string
	Parameters         map[string]interface{}
	Label              string
	Errors             []string
}

func (r *VerifyResult) fail(msg string) *VerifyResult {
	r.Errors = append(r.Errors, msg)
	r.Valid = false
	return r
}

// VerifyRequest is the high-level verification of an RFC 9421-signed HTTP request.
// It locates and parses the Signature-Input and Signature headers, enforces
// freshness and the tag policy, verifies the Content-Digest against the body,
// builds the signing base, gates the algorithm, and verifies the Ed25519
// signature. All failures land in result.Errors; result.Valid is true only if
// every check passed.
func VerifyRequest(method, authority, path string, headers map[string]string, body []byte, publicKey interface{}, opts VerifyRequestOptions) *VerifyResult {
	result := &VerifyResult{}

	if opts.Mode == "" {
		opts.Mode = ModeRFC9421
	}
	if opts.AllowedAlgorithms == nil {
		opts.AllowedAlgorithms = map[string]bool{"ed25519": true}
	}
	if opts.Scheme == "" {
		opts.Scheme = "https"
	}

	norm := make(map[string]string, len(headers))
	for k, v := range headers {
		norm[strings.ToLower(k)] = v
	}

	siValue := norm["signature-input"]
	if siValue == "" {
		return result.fail("Signature-Input header missing")
	}
	sValue := norm["signature"]
	if sValue == "" {
		return result.fail("Signature header missing")
	}

	parsedSI, err := ParseSignatureInput(siValue)
	if err != nil {
		return result.fail("Signature-Input parse error: " + err.Error())
	}
	result.Label = parsedSI.Label
	result.CoveredComponents = parsedSI.CoveredComponents
	result.Parameters = parsedSI.Parameters

	sLabel, sigBytes, err := ParseSignatureValue(sValue)
	if err != nil {
		return result.fail("Signature parse error: " + err.Error())
	}
	if sLabel != "" && parsedSI.Label != "" && sLabel != parsedSI.Label {
		return result.fail(fmt.Sprintf("Signature label %q does not match Signature-Input label %q", sLabel, parsedSI.Label))
	}

	now := time.Now().Unix()
	if opts.Now != nil {
		now = *opts.Now
	}
	freshErr := CheckFreshness(parsedSI.Parameters, parsedSI.CoveredComponents, FreshnessOptions{
		Now:            now,
		MaxAgeSeconds:  opts.MaxAgeSeconds,
		MaxSkewSeconds: opts.MaxSkewSeconds,
		EnforceExpires: opts.EnforceExpires,
		RequireCreated: opts.RequireCreated,
		ParamsSigned:   opts.Mode == ModeRFC9421,
	})
	if freshErr != nil {
		return result.fail("Freshness check failed: " + freshErr.Error())
	}

	tagValue, hasTag := parsedSI.Parameters["tag"]
	if opts.RequireTag && !hasTag {
		return result.fail("Signature 'tag' parameter required but absent")
	}
	if opts.HasExpectedTag {
		tagStr, _ := tagValue.(string)
		if !hasTag || tagStr != opts.ExpectedTag {
			return result.fail(fmt.Sprintf("Signature 'tag' %v does not match expected %q", tagValue, opts.ExpectedTag))
		}
	}

	if opts.RequireContentDigest {
		cdHeader := norm["content-digest"]
		if cdHeader == "" {
			return result.fail("Content-Digest header required but missing")
		}
		covered := false
		for _, c := range parsedSI.CoveredComponents {
			if strings.ToLower(strings.Trim(strings.TrimSpace(c), `"`)) == "content-digest" {
				covered = true
				break
			}
		}
		if !covered {
			return result.fail("Content-Digest required but not a covered signature component")
		}
		if cdErr := VerifyContentDigest(body, cdHeader, opts.RequireAlgorithm); cdErr != nil {
			return result.fail("Content-Digest verification failed: " + cdErr.Error())
		}
		result.ContentDigestValid = true
	} else {
		result.ContentDigestValid = true
	}

	var sprRaw *string
	if opts.Mode == ModeRFC9421 {
		sprRaw = &parsedSI.ParamsBlock
	}
	signingBase, sbErr := BuildSigningBase(SigningBaseInput{
		CoveredComponents:  parsedSI.CoveredComponents,
		Method:             &method,
		Authority:          &authority,
		Path:               &path,
		Scheme:             &opts.Scheme,
		Headers:            norm,
		Parameters:         parsedSI.Parameters,
		Mode:               opts.Mode,
		SignatureParamsRaw: sprRaw,
	})
	if sbErr != nil {
		return result.fail("Signing-base build error: " + sbErr.Error())
	}
	result.SigningBase = signingBase

	// Algorithm-downgrade hardening: an absent alg is ambiguous and a
	// downgrade-by-omission vector, so reject it, then pin to the allow-list.
	algRaw, hasAlg := parsedSI.Parameters["alg"]
	if !hasAlg {
		return result.fail("Signature-Input missing 'alg' parameter")
	}
	alg, ok := algRaw.(string)
	if !ok {
		return result.fail(fmt.Sprintf("Signature-Input 'alg' parameter must be string, got %T", algRaw))
	}
	if !opts.AllowedAlgorithms[strings.ToLower(alg)] {
		return result.fail(fmt.Sprintf("Signature algorithm %q is not in the allowed set", alg))
	}

	sigOK, verr := VerifySignature(signingBase, sigBytes, publicKey, alg)
	if verr != nil {
		return result.fail("Signature verification setup error: " + verr.Error())
	}
	if !sigOK {
		return result.fail("Ed25519 signature does not verify against signing base")
	}
	result.SignatureValid = true

	if opts.NonceSeen != nil {
		if nonceValue, hasNonce := parsedSI.Parameters["nonce"]; hasNonce {
			keyid := ""
			if k, ok := parsedSI.Parameters["keyid"]; ok {
				keyid = fmt.Sprint(k)
			}
			already, nerr := opts.NonceSeen(fmt.Sprint(nonceValue), keyid)
			if nerr != nil {
				return result.fail("Nonce store check errored: " + nerr.Error())
			}
			if already {
				return result.fail("Signature nonce has already been used (replay)")
			}
		}
	}

	result.Valid = result.SignatureValid && result.ContentDigestValid
	return result
}
