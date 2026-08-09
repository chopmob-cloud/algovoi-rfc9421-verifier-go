package verifier

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"regexp"
	"strings"
)

// ContentDigestError is returned when Content-Digest (RFC 9530) verification fails.
type ContentDigestError struct{ msg string }

func (e *ContentDigestError) Error() string { return e.msg }

func newContentDigestError(format string, a ...interface{}) *ContentDigestError {
	return &ContentDigestError{msg: fmt.Sprintf(format, a...)}
}

var digestEntryRE = regexp.MustCompile(`([a-z0-9-]+)=:([A-Za-z0-9+/=]+):`)

func newHasher(algo string) (hash.Hash, bool) {
	switch algo {
	case "sha-256":
		return sha256.New(), true
	case "sha-512":
		return sha512.New(), true
	default:
		return nil, false
	}
}

// ComputeContentDigest computes the Content-Digest header value for a body in the
// structured-fields representation "<algo>=:<base64>:".
func ComputeContentDigest(body []byte, algorithm string) (string, error) {
	algo := strings.ToLower(algorithm)
	h, ok := newHasher(algo)
	if !ok {
		return "", newContentDigestError("unsupported algorithm %q; supported: [sha-256 sha-512]", algorithm)
	}
	h.Write(body)
	sum := h.Sum(nil)
	return algo + "=:" + base64.StdEncoding.EncodeToString(sum) + ":", nil
}

// VerifyContentDigest verifies that the Content-Digest header matches the body.
//
// If requireAlgorithm is non-empty, at least one entry must use that algorithm and
// verify. Every recognized entry must verify. If no entry uses a recognized
// algorithm, verification fails closed (nothing was verified).
func VerifyContentDigest(body []byte, headerValue string, requireAlgorithm string) error {
	entries := digestEntryRE.FindAllStringSubmatch(headerValue, -1)
	if len(entries) == 0 {
		return newContentDigestError("no valid digest entries in header: %q", headerValue)
	}

	var requiredAlg string
	if requireAlgorithm != "" {
		requiredAlg = strings.ToLower(requireAlgorithm)
	}
	requiredSeen := false
	verifiedAny := false

	for _, e := range entries {
		algo := strings.ToLower(e[1])
		digestB64 := e[2]
		h, ok := newHasher(algo)
		if !ok {
			// Unknown algorithms are skipped per RFC 9530.
			continue
		}
		if requiredAlg != "" && algo == requiredAlg {
			requiredSeen = true
		}
		expected, err := base64.StdEncoding.DecodeString(digestB64)
		if err != nil {
			return newContentDigestError("digest entry %q is not valid base64: %v", algo, err)
		}
		// Reject non-canonical base64 (non-zero pad bits): same malleability reason
		// as the signature value.
		if base64.StdEncoding.EncodeToString(expected) != digestB64 {
			return newContentDigestError("digest entry %q is not canonical base64 (non-zero pad bits)", algo)
		}
		h.Write(body)
		actual := h.Sum(nil)
		if !bytesEqual(expected, actual) {
			return newContentDigestError("digest mismatch on %s: header claims %s but body hashes to %s",
				algo, digestB64, base64.StdEncoding.EncodeToString(actual))
		}
		verifiedAny = true
	}

	if requiredAlg != "" && !requiredSeen {
		return newContentDigestError("required algorithm %q not present in header", requiredAlg)
	}
	if !verifiedAny {
		return newContentDigestError("no recognized digest algorithm in Content-Digest header; nothing verified")
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
