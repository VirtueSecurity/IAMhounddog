package policies

import (
	"regexp"
	"strings"
)

// Helper function to match wildcard IAM names
func ResourceMatcher(pattern string) func(string) bool {
	if !HasWildcard(pattern) {
		return func(candidate string) bool { return candidate == pattern }
	}

	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")

	re, err := regexp.Compile(b.String())
	if err != nil {
		return func(string) bool { return false }
	}

	return re.MatchString
}

func HasWildcard(pattern string) bool {
	return strings.ContainsAny(pattern, "*?")
}
