// Package verifier is the Go port of algovoi-rfc9421-verifier: the core RFC 9421
// (HTTP Message Signatures) plus RFC 9530 (Content-Digest) verifier.
//
// It reproduces the reference Python/TypeScript implementations byte-for-byte:
// signing-base construction (Section 2.5), Signature-Input / Signature parsing,
// the Ed25519 public-key trust-boundary gate (non-canonical, off-curve and
// small-order rejection), Content-Digest verification, and freshness / replay
// window checks.
//
// This package is Ed25519-only and self-contained: it depends on nothing outside
// the Go standard library. The ECDSA algorithms live in a SEPARATE add-on package
// (ecdsa) that imports this one; this core package never imports the add-on.
package verifier

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SigningBaseError is returned when the signing base cannot be constructed.
type SigningBaseError struct{ msg string }

func (e *SigningBaseError) Error() string { return e.msg }

func newSigningBaseError(format string, a ...interface{}) *SigningBaseError {
	return &SigningBaseError{msg: fmt.Sprintf(format, a...)}
}

// Signing-base modes.
const (
	// ModeAlgovoiV0 is the legacy internal format: @method is lowercased and no
	// @signature-params line is appended.
	ModeAlgovoiV0 = "algovoi-v0"
	// ModeRFC9421 is full RFC 9421 Section 2.5 compliance: @method is preserved
	// as supplied and a final @signature-params line carrying SignatureParamsRaw
	// verbatim is appended.
	ModeRFC9421 = "rfc9421"
)

// SigningBaseInput carries the inputs to BuildSigningBase. Optional string and
// integer components are pointers so an absent (nil) component can be
// distinguished from a supplied empty value, mirroring the Python None defaults.
type SigningBaseInput struct {
	CoveredComponents []string
	Method            *string
	Authority         *string
	Path              *string
	TargetURI         *string
	Scheme            *string
	Status            *int
	Headers           map[string]string
	// Parameters carries the Signature-Input parameters (created, expires, ...).
	// Values may be string, int, int64 or json.Number; they are stringified with
	// the same rules as Python str() when a derived component reads them.
	Parameters map[string]interface{}
	Mode       string
	// SignatureParamsRaw is the post-label portion of the Signature-Input header
	// value (the Inner List plus parameters block, exactly as on the wire).
	// Required when Mode is ModeRFC9421.
	SignatureParamsRaw *string
}

// paramToString reproduces Python str() for the parameter values that can appear
// in a signing base (created / expires), which are ints or strings in practice.
func paramToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		// Integral floats print without a decimal point, matching Python str(int).
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// BuildSigningBase builds the RFC 9421 signing base from the ordered covered
// components. It returns the newline-joined signing base string; the bytes to be
// signed / verified are that string UTF-8 encoded.
func BuildSigningBase(in SigningBaseInput) (string, error) {
	if in.Mode != ModeAlgovoiV0 && in.Mode != ModeRFC9421 {
		return "", newSigningBaseError("mode must be %q or %q, got %q", ModeAlgovoiV0, ModeRFC9421, in.Mode)
	}
	if in.Mode == ModeRFC9421 && in.SignatureParamsRaw == nil {
		return "", newSigningBaseError(
			"rfc9421 mode requires SignatureParamsRaw (the post-label portion of the Signature-Input header)")
	}

	// Lower-case header keys for case-insensitive lookup.
	headers := make(map[string]string, len(in.Headers))
	for k, v := range in.Headers {
		headers[strings.ToLower(k)] = v
	}

	lines := make([]string, 0, len(in.CoveredComponents)+1)
	for _, component := range in.CoveredComponents {
		c := strings.ToLower(component)
		var value string

		switch {
		case c == "@method":
			if in.Method == nil {
				return "", newSigningBaseError("@method covered but method not supplied")
			}
			if in.Mode == ModeRFC9421 {
				value = *in.Method
			} else {
				value = strings.ToLower(*in.Method)
			}
		case c == "@authority":
			if in.Authority == nil {
				return "", newSigningBaseError("@authority covered but authority not supplied")
			}
			value = strings.ToLower(*in.Authority)
		case c == "@path":
			if in.Path == nil {
				return "", newSigningBaseError("@path covered but path not supplied")
			}
			value = *in.Path
		case c == "@target-uri":
			if in.TargetURI == nil {
				return "", newSigningBaseError("@target-uri covered but target_uri not supplied")
			}
			value = *in.TargetURI
		case c == "@scheme":
			if in.Scheme == nil {
				return "", newSigningBaseError("@scheme covered but scheme not supplied")
			}
			value = strings.ToLower(*in.Scheme)
		case c == "@status":
			if in.Status == nil {
				return "", newSigningBaseError("@status covered but status not supplied")
			}
			value = strconv.Itoa(*in.Status)
		case c == "created":
			v, ok := in.Parameters["created"]
			if !ok {
				return "", newSigningBaseError("'created' covered but no 'created' parameter in Signature-Input")
			}
			value = paramToString(v)
		case c == "expires":
			v, ok := in.Parameters["expires"]
			if !ok {
				return "", newSigningBaseError("'expires' covered but no 'expires' parameter in Signature-Input")
			}
			value = paramToString(v)
		case strings.HasPrefix(c, "@"):
			return "", newSigningBaseError("unsupported derived component: %q", component)
		default:
			v, ok := headers[c]
			if !ok {
				return "", newSigningBaseError("covered header %q not present in supplied headers", component)
			}
			value = v
		}

		lines = append(lines, `"`+c+`": `+value)
	}

	if in.Mode == ModeRFC9421 {
		lines = append(lines, `"@signature-params": `+*in.SignatureParamsRaw)
	}

	return strings.Join(lines, "\n"), nil
}
