package verifier

import (
	"fmt"
	"strconv"
	"strings"
)

// FreshnessError is returned when a signature is stale, not yet valid, expired, or
// malformed in its time parameters.
type FreshnessError struct{ msg string }

func (e *FreshnessError) Error() string { return e.msg }

func newFreshnessError(format string, a ...interface{}) *FreshnessError {
	return &FreshnessError{msg: fmt.Sprintf(format, a...)}
}

// FreshnessOptions controls the freshness / replay-window check.
//
// MaxAgeSeconds is a pointer so that nil means "no age check" (the library
// default); a concrete value opts in to a window.
type FreshnessOptions struct {
	Now            int64
	MaxAgeSeconds  *int64
	MaxSkewSeconds int64
	EnforceExpires bool
	RequireCreated bool
	// ParamsSigned is true in RFC 9421 mode, where @signature-params (carrying
	// created / expires) is part of the signing base, so a parameter is trustworthy
	// even when it is not also listed as a covered component.
	ParamsSigned bool
}

func coveredNames(coveredComponents []string) map[string]bool {
	names := map[string]bool{}
	for _, component := range coveredComponents {
		name := strings.Trim(strings.TrimSpace(component), `"`)
		name = strings.SplitN(name, ";", 2)[0]
		name = strings.ToLower(strings.Trim(strings.TrimSpace(name), `"`))
		if name != "" {
			names[name] = true
		}
	}
	return names
}

func asInt(value interface{}, name string) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, newFreshnessError("'%s' is not an integer: %q", name, v)
		}
		return n, nil
	case float64:
		return int64(v), nil
	default:
		return 0, newFreshnessError("'%s' is not an integer: %v", name, value)
	}
}

// CheckFreshness validates the time-based signature parameters. It is a no-op when
// there is nothing to check. Only signed (covered, or params-signed in RFC 9421
// mode) created / expires values are honoured; an unsigned timestamp fails closed.
func CheckFreshness(parameters map[string]interface{}, coveredComponents []string, opts FreshnessOptions) error {
	covered := coveredNames(coveredComponents)
	created, hasCreated := parameters["created"]
	expires, hasExpires := parameters["expires"]

	signed := func(name string) bool {
		return covered[name] || opts.ParamsSigned
	}

	if opts.MaxAgeSeconds != nil || opts.RequireCreated {
		if !hasCreated {
			return newFreshnessError("freshness required but no 'created' parameter present")
		}
		if !signed("created") {
			return newFreshnessError("freshness required but 'created' is not signed (not a covered component and params are unsigned)")
		}
		createdI, err := asInt(created, "created")
		if err != nil {
			return err
		}
		if createdI > opts.Now+opts.MaxSkewSeconds {
			return newFreshnessError("signature 'created' is in the future beyond the allowed skew")
		}
		if opts.MaxAgeSeconds != nil && createdI < opts.Now-*opts.MaxAgeSeconds {
			return newFreshnessError("signature is older than the maximum allowed age")
		}
	}

	if opts.EnforceExpires && hasExpires {
		if !signed("expires") {
			return newFreshnessError("'expires' present but not signed (not a covered component and params are unsigned)")
		}
		expiresI, err := asInt(expires, "expires")
		if err != nil {
			return err
		}
		if opts.Now > expiresI+opts.MaxSkewSeconds {
			return newFreshnessError("signature has expired")
		}
	}

	return nil
}
