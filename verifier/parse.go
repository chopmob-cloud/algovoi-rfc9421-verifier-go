package verifier

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SignatureInputParseError is returned when a Signature-Input or Signature header
// cannot be parsed.
type SignatureInputParseError struct{ msg string }

func (e *SignatureInputParseError) Error() string { return e.msg }

func newParseError(format string, a ...interface{}) *SignatureInputParseError {
	return &SignatureInputParseError{msg: fmt.Sprintf(format, a...)}
}

// ParsedSignatureInput is a parsed Signature-Input header for a single label.
type ParsedSignatureInput struct {
	Label             string
	CoveredComponents []string
	// Parameters values are either string or int64 (matching the reference which
	// stores quoted values as strings and unquoted integer-looking values as ints).
	Parameters  map[string]interface{}
	Raw         string
	ParamsBlock string
}

var (
	// Anchored at the start of the (already left-trimmed) header value.
	labelRE   = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*`)
	coveredRE = regexp.MustCompile(`^\(\s*(?:"[^"]*"\s*)*\)`)
	quotedRE  = regexp.MustCompile(`"([^"]*)"`)
	paramRE   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]*)=([^;,\s]+|"[^"]*")`)
)

// ParseSignatureInput parses a Signature-Input header value. It accepts the
// strict RFC 9421 labelled form and the unlabelled form (label defaults to "").
func ParseSignatureInput(headerValue string) (*ParsedSignatureInput, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return nil, newParseError("empty header value")
	}

	var label, rest string
	if m := labelRE.FindStringSubmatchIndex(headerValue); m != nil {
		label = headerValue[m[2]:m[3]]
		rest = headerValue[m[1]:]
	} else if strings.HasPrefix(headerValue, "(") {
		label = ""
		rest = headerValue
	} else {
		return nil, newParseError("no label or covered-components list found at start: %q", truncate(headerValue, 40))
	}

	// The post-label portion, captured verbatim for the @signature-params line.
	paramsBlock := rest

	loc := coveredRE.FindStringIndex(rest)
	if loc == nil {
		return nil, newParseError("no covered-components list found")
	}
	coveredRaw := rest[loc[0]:loc[1]]
	covered := []string{}
	for _, sm := range quotedRE.FindAllStringSubmatch(coveredRaw, -1) {
		covered = append(covered, sm[1])
	}
	rest = rest[loc[1]:]

	parameters := map[string]interface{}{}
	for _, sm := range paramRE.FindAllStringSubmatch(rest, -1) {
		key := sm[1]
		rawVal := sm[2]
		if strings.HasPrefix(rawVal, `"`) && strings.HasSuffix(rawVal, `"`) {
			parameters[key] = rawVal[1 : len(rawVal)-1]
		} else if n, err := strconv.ParseInt(rawVal, 10, 64); err == nil {
			parameters[key] = n
		} else {
			parameters[key] = rawVal
		}
	}

	return &ParsedSignatureInput{
		Label:             label,
		CoveredComponents: covered,
		Parameters:        parameters,
		Raw:               headerValue,
		ParamsBlock:       paramsBlock,
	}, nil
}

// ParseSignatureValue parses a Signature header value and returns (label, bytes).
// It rejects non-canonical base64 (encodings whose trailing pad bits are non-zero
// and therefore do not round-trip), matching the reference: several header
// encodings would otherwise decode to the same signature and all verify, which is
// a signature-string malleability class.
func ParseSignatureValue(headerValue string) (string, []byte, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return "", nil, newParseError("empty Signature header value")
	}

	var label, rest string
	if m := labelRE.FindStringSubmatchIndex(headerValue); m != nil {
		label = headerValue[m[2]:m[3]]
		rest = strings.TrimSpace(headerValue[m[1]:])
	} else if strings.HasPrefix(headerValue, ":") {
		label = ""
		rest = headerValue
	} else {
		return "", nil, newParseError("no label or signature-value prefix found at start: %q", truncate(headerValue, 40))
	}

	if !strings.HasPrefix(rest, ":") || !strings.HasSuffix(rest, ":") {
		return "", nil, newParseError("signature value must be wrapped in colons (RFC 8941 byte-sequence form)")
	}
	sigB64 := rest[1 : len(rest)-1]
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", nil, newParseError("signature value is not valid base64: %v", err)
	}
	if base64.StdEncoding.EncodeToString(sigBytes) != sigB64 {
		return "", nil, newParseError("signature value is not canonical base64 (non-zero pad bits)")
	}
	return label, sigBytes, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
