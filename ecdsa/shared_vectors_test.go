package ecdsa

// Cross-language ECDSA differential test against the SHARED reference vectors.
//
// Loads reference_ecdsa_v0.json (the same file the Rust/Python/TS add-ons run
// against) and asserts that this package's VerifyP256 / VerifyP384 agree with
// expect_valid for every entry: valid vectors verify true, tampered vectors
// verify false. Passing this in both Go and Rust proves cross-language ECDSA
// parity against one shared set.
//
// msg_hex is the raw signing base the add-on verifies over; the public API
// hashes it internally (SHA-256 for P-256, SHA-384 for P-384), so we pass the
// decoded message bytes as the signing base and let the package hash.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type sharedVector struct {
	MsgHex             string `json:"msg_hex"`
	PubUncompressedHex string `json:"pub_uncompressed_hex"`
	SigRawHex          string `json:"sig_raw_hex"`
	ExpectValid        bool   `json:"expect_valid"`
}

type sharedVectors struct {
	P256 []sharedVector `json:"p256"`
	P384 []sharedVector `json:"p384"`
}

// Default relative to this package directory (go test sets the CWD to the
// package dir), pointing at the sibling multilang repo that holds the shared
// vectors. Override with ALGOVOI_REFERENCE_ECDSA_VECTORS; when neither resolves,
// the test skips rather than fails, so the suite stays green without that
// third checkout.
const sharedVectorsPath = "../../algovoi-rfc9421-verifier-multilang/vectors/reference_ecdsa_v0.json"

func runSharedVectors(t *testing.T, vectors []sharedVector, verify verifierFunc, label string) (pass, total int) {
	t.Helper()
	total = len(vectors)
	for i, v := range vectors {
		msg, err := hex.DecodeString(v.MsgHex)
		if err != nil {
			t.Fatalf("%s[%d]: bad msg_hex: %v", label, i, err)
		}
		sig, err := hex.DecodeString(v.SigRawHex)
		if err != nil {
			t.Fatalf("%s[%d]: bad sig_raw_hex: %v", label, i, err)
		}
		pub, err := hex.DecodeString(v.PubUncompressedHex)
		if err != nil {
			t.Fatalf("%s[%d]: bad pub_uncompressed_hex: %v", label, i, err)
		}
		got, err := verify(string(msg), sig, pub)
		if err != nil {
			t.Fatalf("%s[%d]: unexpected setup error: %v", label, i, err)
		}
		if got != v.ExpectValid {
			t.Errorf("%s[%d]: verify returned %v, expected %v", label, i, got, v.ExpectValid)
			continue
		}
		pass++
	}
	return pass, total
}

func TestSharedVectorsCrossLanguageParity(t *testing.T) {
	path := os.Getenv("ALGOVOI_REFERENCE_ECDSA_VECTORS")
	if path == "" {
		path = sharedVectorsPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("shared vectors not available at %q (%v); set ALGOVOI_REFERENCE_ECDSA_VECTORS to run", path, err)
	}
	var vectors sharedVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse shared vectors: %v", err)
	}

	p256Pass, p256Total := runSharedVectors(t, vectors.P256, VerifyP256, "p256")
	p384Pass, p384Total := runSharedVectors(t, vectors.P384, VerifyP384, "p384")

	t.Logf("shared_vectors: p256 %d/%d, p384 %d/%d", p256Pass, p256Total, p384Pass, p384Total)
	if p256Pass != p256Total {
		t.Errorf("not all p256 shared vectors matched: %d/%d", p256Pass, p256Total)
	}
	if p384Pass != p384Total {
		t.Errorf("not all p384 shared vectors matched: %d/%d", p384Pass, p384Total)
	}
}
