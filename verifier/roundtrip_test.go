package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// TestVerifyRequestRoundTrip signs a request with a generated Ed25519 key and
// verifies it through the high-level VerifyRequest path (parse, freshness,
// content-digest coverage, signing-base build, algorithm gate, signature check).
func TestVerifyRequestRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	method := "POST"
	authority := "api.algovoi.co.uk"
	path := "/pay"
	body := []byte(`{"amount":100}`)

	cd, err := ComputeContentDigest(body, "sha-256")
	if err != nil {
		t.Fatalf("content-digest: %v", err)
	}

	created := int64(1778955520)
	paramsBlock := `("@method" "@authority" "@path" "content-digest");created=1778955520;keyid="did:web:api";alg="ed25519"`

	sb, err := BuildSigningBase(SigningBaseInput{
		CoveredComponents:  []string{"@method", "@authority", "@path", "content-digest"},
		Method:             &method,
		Authority:          &authority,
		Path:               &path,
		Headers:            map[string]string{"content-digest": cd},
		Parameters:         map[string]interface{}{"created": created, "keyid": "did:web:api", "alg": "ed25519"},
		Mode:               ModeRFC9421,
		SignatureParamsRaw: &paramsBlock,
	})
	if err != nil {
		t.Fatalf("signing base: %v", err)
	}

	sig := ed25519.Sign(priv, []byte(sb))
	headers := map[string]string{
		"Signature-Input": "sig=" + paramsBlock,
		"Signature":       "sig=:" + base64.StdEncoding.EncodeToString(sig) + ":",
		"Content-Digest":  cd,
	}

	opts := DefaultVerifyRequestOptions()
	now := created
	opts.Now = &now

	res := VerifyRequest(method, authority, path, headers, body, []byte(pub), opts)
	if !res.Valid {
		t.Fatalf("expected valid, got errors: %v", res.Errors)
	}
	if !res.SignatureValid || !res.ContentDigestValid {
		t.Fatalf("sub-results: sig=%v cd=%v", res.SignatureValid, res.ContentDigestValid)
	}

	// Tamper the body: content-digest no longer matches, verification fails.
	res = VerifyRequest(method, authority, path, headers, []byte(`{"amount":999}`), []byte(pub), opts)
	if res.Valid {
		t.Fatal("verification passed on a tampered body (should not)")
	}
}

// TestNonCanonicalBase64Rejected confirms the parser rejects a signature whose
// base64 encoding has non-zero trailing pad bits (a signature-string malleability
// class), matching the reference guard.
func TestNonCanonicalBase64Rejected(t *testing.T) {
	// 64 zero bytes canonically encode with a trailing "==". Flipping a pad bit
	// (the final "=" region) yields an alias that decodes to the same bytes.
	canonical := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if _, _, err := ParseSignatureValue("sig=:" + canonical + ":"); err != nil {
		t.Fatalf("canonical base64 unexpectedly rejected: %v", err)
	}
	// Replace the last 'A' before the padding with 'B' so the same decoded bytes
	// have a non-canonical encoding. "AAA=" -> "AAB=" keeps length but sets pad bits.
	nonCanonical := canonical[:len(canonical)-2] + "B="
	if _, _, err := ParseSignatureValue("sig=:" + nonCanonical + ":"); err == nil {
		t.Fatal("expected non-canonical base64 to be rejected")
	}
}
