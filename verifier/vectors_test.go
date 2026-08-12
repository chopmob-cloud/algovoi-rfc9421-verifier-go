package verifier

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Default location of the frozen cross-language reference vectors: the
// multilang repo checked out alongside this one (go test sets the CWD to the
// package dir, so this is relative to verifier/). Override with the
// ALGOVOI_REFERENCE_VECTORS environment variable if it lives elsewhere. When
// neither resolves, the frozen-vector tests skip rather than fail, so the suite
// stays green without that third checkout.
const defaultVectorsPath = `../../algovoi-rfc9421-verifier-multilang/vectors/reference_vectors_v0.json`

type sbInput struct {
	CoveredComponents []string               `json:"covered_components"`
	Method            *string                `json:"method"`
	Authority         *string                `json:"authority"`
	Path              *string                `json:"path"`
	TargetURI         *string                `json:"target_uri"`
	Scheme            *string                `json:"scheme"`
	Status            *int                   `json:"status"`
	Headers           map[string]string      `json:"headers"`
	Parameters        map[string]interface{} `json:"parameters"`
}

type sbCase struct {
	In                 sbInput `json:"in"`
	Mode               string  `json:"mode"`
	OK                 bool    `json:"ok"`
	SigningBaseB64     string  `json:"signing_base_b64"`
	SignatureParamsRaw *string `json:"signature_params_raw"`
}

type keygateCase struct {
	PkHex      string  `json:"pk_hex"`
	SmallOrder bool    `json:"small_order"`
	Rejected   *string `json:"rejected"`
}

type ed25519Case struct {
	SigningBaseB64 string `json:"signing_base_b64"`
	SigHex         string `json:"sig_hex"`
	PkHex          string `json:"pk_hex"`
	ExpectValid    bool   `json:"expect_valid"`
}

type referenceVectors struct {
	SigningBase   []sbCase      `json:"signing_base"`
	Keygate       []keygateCase `json:"keygate"`
	Ed25519Verify []ed25519Case `json:"ed25519_verify"`
}

func loadVectors(t *testing.T) *referenceVectors {
	t.Helper()
	path := os.Getenv("ALGOVOI_REFERENCE_VECTORS")
	if path == "" {
		path = defaultVectorsPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("reference vectors not available at %s (%v); set ALGOVOI_REFERENCE_VECTORS to run", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep integer parameters as json.Number, matching Python str(int)
	var v referenceVectors
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("cannot parse reference vectors: %v", err)
	}
	return &v
}

func TestFrozenVectorsSigningBase(t *testing.T) {
	v := loadVectors(t)
	if len(v.SigningBase) == 0 {
		t.Fatal("no signing_base vectors loaded")
	}
	passed := 0
	for i, c := range v.SigningBase {
		want, err := base64.StdEncoding.DecodeString(c.SigningBaseB64)
		if err != nil {
			t.Fatalf("case %d: bad signing_base_b64: %v", i, err)
		}
		in := SigningBaseInput{
			CoveredComponents:  c.In.CoveredComponents,
			Method:             c.In.Method,
			Authority:          c.In.Authority,
			Path:               c.In.Path,
			TargetURI:          c.In.TargetURI,
			Scheme:             c.In.Scheme,
			Status:             c.In.Status,
			Headers:            c.In.Headers,
			Parameters:         c.In.Parameters,
			Mode:               c.Mode,
			SignatureParamsRaw: c.SignatureParamsRaw,
		}
		got, err := BuildSigningBase(in)
		if !c.OK {
			if err == nil {
				t.Errorf("case %d (mode %s): expected error, got none", i, c.Mode)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d (mode %s): unexpected error: %v", i, c.Mode, err)
			continue
		}
		if !bytes.Equal([]byte(got), want) {
			t.Errorf("case %d (mode %s): signing base mismatch\n got: %q\nwant: %q", i, c.Mode, got, string(want))
			continue
		}
		passed++
	}
	t.Logf("signing_base: %d/%d passed", passed, len(v.SigningBase))
	if passed != len(v.SigningBase) {
		t.Fatalf("signing_base: only %d/%d passed", passed, len(v.SigningBase))
	}
}

func TestFrozenVectorsKeygate(t *testing.T) {
	v := loadVectors(t)
	if len(v.Keygate) == 0 {
		t.Fatal("no keygate vectors loaded")
	}
	passed := 0
	for i, c := range v.Keygate {
		pk, err := hex.DecodeString(c.PkHex)
		if err != nil {
			t.Fatalf("case %d: bad pk_hex: %v", i, err)
		}
		gotRejected := CheckEd25519PublicKey(pk) != nil
		wantRejected := c.Rejected != nil
		if gotRejected != wantRejected {
			t.Errorf("case %d (pk %s): rejected=%v, want %v", i, c.PkHex, gotRejected, wantRejected)
			continue
		}
		if got := IsSmallOrder(pk); got != c.SmallOrder {
			t.Errorf("case %d (pk %s): small_order=%v, want %v", i, c.PkHex, got, c.SmallOrder)
			continue
		}
		passed++
	}
	t.Logf("keygate: %d/%d passed", passed, len(v.Keygate))
	if passed != len(v.Keygate) {
		t.Fatalf("keygate: only %d/%d passed", passed, len(v.Keygate))
	}
}

func TestFrozenVectorsEd25519Verify(t *testing.T) {
	v := loadVectors(t)
	if len(v.Ed25519Verify) == 0 {
		t.Fatal("no ed25519_verify vectors loaded")
	}
	passed := 0
	for i, c := range v.Ed25519Verify {
		sbBytes, err := base64.StdEncoding.DecodeString(c.SigningBaseB64)
		if err != nil {
			t.Fatalf("case %d: bad signing_base_b64: %v", i, err)
		}
		sig, err := hex.DecodeString(c.SigHex)
		if err != nil {
			t.Fatalf("case %d: bad sig_hex: %v", i, err)
		}
		ok, verr := VerifySignature(string(sbBytes), sig, c.PkHex, "ed25519")
		valid := verr == nil && ok
		if valid != c.ExpectValid {
			t.Errorf("case %d: valid=%v (err=%v), want %v", i, valid, verr, c.ExpectValid)
			continue
		}
		passed++
	}
	t.Logf("ed25519_verify: %d/%d passed", passed, len(v.Ed25519Verify))
	if passed != len(v.Ed25519Verify) {
		t.Fatalf("ed25519_verify: only %d/%d passed", passed, len(v.Ed25519Verify))
	}
}
