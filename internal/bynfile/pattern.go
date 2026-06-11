package bynfile

// pattern.go implements action-string pattern matching for [aliases] and
// action entries that may contain typed placeholders.
//
// Tokenization uses strings.Fields throughout, which is consistent with the
// shipped matcher in the daemon (strings.Fields + slices.Equal). This means
// action strings with literal internal spaces cannot be encoded as a single
// token; that limitation is documented and unchanged.
//
// Wildcard action "*" is handled by ActionsAllowAll() before the pattern layer
// is reached; ParseActionPattern("*") therefore accepts "*" as a plain literal
// token to avoid special-casing here.

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// tokenKind distinguishes how a token in a compiled Pattern must be matched.
type tokenKind int

const (
	kindLiteral tokenKind = iota
	kindUUID              // {{uuid}}
	kindInt               // {{int}}
	kindAlnum             // {{alnum}}
	kindStr               // {{str}} or {{*}}
	kindPath              // {{path}}
	kindURL               // {{url}} with optional constraints
	kindRe                // {{re:<pattern>}}
	kindArgs              // {{args}} — must be the last token; matches 0..N remaining
)

// token is one compiled element of a Pattern.
type token struct {
	kind    tokenKind
	literal string         // kindLiteral: the required text
	re      *regexp.Regexp // kindRe: anchored compiled pattern
	// URL constraint fields (kindURL):
	urlHost   string // empty = unconstrained
	urlScheme string // empty = unconstrained
}

// Pattern is a compiled action-string pattern. The zero value is invalid; use
// ParseActionPattern to construct one.
type Pattern struct {
	raw    string  // original action string, for display
	tokens []token // compiled token sequence
}

// HasPlaceholders reports whether the pattern contains at least one typed
// placeholder (i.e. it is not a literal-only pattern).
func (p Pattern) HasPlaceholders() bool {
	for _, t := range p.tokens {
		if t.kind != kindLiteral {
			return true
		}
	}
	return false
}

// HasArgsTail reports whether the pattern ends with {{args}}.
func (p Pattern) HasArgsTail() bool {
	if len(p.tokens) == 0 {
		return false
	}
	return p.tokens[len(p.tokens)-1].kind == kindArgs
}

// String returns the original action string.
func (p Pattern) String() string { return p.raw }

// reLiteral is the anchored regexp for a compiled RE placeholder.
// We compile once in parseToken and store it in token.re.

// uuidRe matches RFC-4122 (and RFC-9562) UUID hex-dash form, case-insensitive.
// The pattern is 8-4-4-4-12 hex digits.
var uuidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// intRe matches optional leading minus followed by one or more digits.
var intRe = regexp.MustCompile(`^-?[0-9]+$`)

// alnumRe matches one or more ASCII alphanumeric characters.
var alnumRe = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// parseToken parses one token string (stripped of surrounding {{}}). It returns
// the compiled token or an error naming the bad type.
func parseToken(raw string) (token, error) {
	inner := raw
	if strings.HasPrefix(raw, "{{") && strings.HasSuffix(raw, "}}") {
		inner = raw[2 : len(raw)-2]
	}

	switch {
	case inner == "uuid":
		return token{kind: kindUUID}, nil
	case inner == "int":
		return token{kind: kindInt}, nil
	case inner == "alnum":
		return token{kind: kindAlnum}, nil
	case inner == "str" || inner == "*":
		return token{kind: kindStr}, nil
	case inner == "path":
		return token{kind: kindPath}, nil
	case inner == "args":
		return token{kind: kindArgs}, nil
	case inner == "url":
		return token{kind: kindURL}, nil
	case strings.HasPrefix(inner, "url:"):
		return parseURLToken(inner[4:])
	case strings.HasPrefix(inner, "re:"):
		return parseReToken(inner[3:])
	default:
		return token{}, fmt.Errorf("unknown placeholder type %q in {{%s}}: valid types are uuid, int, alnum, str, path, url, re:<pattern>, args", inner, inner)
	}
}

// parseURLToken parses the constraint list after "url:".
// Constraints are comma-separated: host=<exact-host> and/or scheme=<scheme>.
func parseURLToken(constraints string) (token, error) {
	t := token{kind: kindURL}
	parts := strings.Split(constraints, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || kv[1] == "" {
			return token{}, fmt.Errorf("invalid url constraint %q: expected key=value (host=<host> or scheme=<scheme>)", part)
		}
		switch kv[0] {
		case "host":
			t.urlHost = kv[1]
		case "scheme":
			t.urlScheme = kv[1]
		default:
			return token{}, fmt.Errorf("unknown url constraint key %q: allowed keys are host, scheme", kv[0])
		}
	}
	return t, nil
}

// parseReToken compiles the RE2 pattern with implicit anchoring ^(?:...)$.
func parseReToken(pattern string) (token, error) {
	anchored := `^(?:` + pattern + `)$`
	re, err := regexp.Compile(anchored)
	if err != nil {
		return token{}, fmt.Errorf("re: pattern %q does not compile: %w", pattern, err)
	}
	return token{kind: kindRe, re: re}, nil
}

// ParseActionPattern validates and compiles one action entry string. Literal-only
// entries (zero placeholders) are valid patterns. Returns a compiled Pattern.
//
// The special action "*" is accepted as a plain literal token. It is never
// passed to the matcher in practice (ActionsAllowAll returns true first), but
// accepting it here avoids special-casing in callers.
//
// {{args}} is valid ONLY as the final token; anywhere else is a validation
// error.
func ParseActionPattern(action string) (Pattern, error) {
	fields := strings.Fields(action)
	if len(fields) == 0 {
		// Empty / whitespace-only string → single literal empty token so that
		// Match("") works correctly, but we use the raw form consistently.
		// Actually an empty action is unusual; return a valid zero-token pattern.
		return Pattern{raw: action}, nil
	}

	tokens := make([]token, 0, len(fields))
	for i, f := range fields {
		if isPlaceholder(f) {
			tok, err := parseToken(f)
			if err != nil {
				return Pattern{}, err
			}
			// {{args}} may only appear as the final token.
			if tok.kind == kindArgs && i != len(fields)-1 {
				return Pattern{}, fmt.Errorf("{{args}} may only appear as the final token of an action; found at position %d in %q", i, action)
			}
			tokens = append(tokens, tok)
		} else {
			// Literal token.
			tokens = append(tokens, token{kind: kindLiteral, literal: f})
		}
	}

	return Pattern{raw: action, tokens: tokens}, nil
}

// isPlaceholder reports whether a field token is a {{...}} expression.
func isPlaceholder(s string) bool {
	return strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}")
}

// Match reports whether argv satisfies the pattern.
//
// Rules:
//   - For a literal token, the corresponding argv element must equal it exactly.
//   - For a typed placeholder, the corresponding argv element must satisfy the
//     type constraint.
//   - {{args}} (final only) absorbs zero or more remaining argv elements.
//   - If the pattern has no {{args}} tail, len(argv) must equal len(tokens).
func (p Pattern) Match(argv []string) bool {
	tokens := p.tokens
	n := len(tokens)

	if n == 0 {
		return len(argv) == 0
	}

	hasArgsTail := tokens[n-1].kind == kindArgs
	if hasArgsTail {
		// The non-tail tokens must match argv[0:n-1], and then any remaining are absorbed.
		if len(argv) < n-1 {
			return false
		}
		for i, tok := range tokens[:n-1] {
			if !matchToken(tok, argv[i]) { //nolint:gosec // G602: bounds checked above (len(argv) >= n-1)
				return false
			}
		}
		return true
	}

	// No {{args}} tail: argv must be exactly as long as the token list.
	if len(argv) != n {
		return false
	}
	for i, tok := range tokens {
		if !matchToken(tok, argv[i]) { //nolint:gosec // G602: bounds checked above (len(argv) == n)
			return false
		}
	}
	return true
}

// matchToken reports whether a single argv element satisfies tok.
func matchToken(tok token, arg string) bool {
	switch tok.kind {
	case kindLiteral:
		return arg == tok.literal
	case kindUUID:
		return uuidRe.MatchString(arg)
	case kindInt:
		return intRe.MatchString(arg)
	case kindAlnum:
		return alnumRe.MatchString(arg)
	case kindStr:
		return true // any single token
	case kindPath:
		// Any single token without a NUL byte. This is syntactic only; we do
		// not validate the path against the filesystem.
		return !strings.ContainsRune(arg, 0)
	case kindURL:
		u, err := url.Parse(arg)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return false
		}
		if tok.urlHost != "" && u.Hostname() != tok.urlHost {
			return false
		}
		if tok.urlScheme != "" && u.Scheme != tok.urlScheme {
			return false
		}
		return true
	case kindRe:
		return tok.re.MatchString(arg)
	case kindArgs:
		// Should not be called via matchToken; handled in Match directly.
		// Return true defensively (it absorbs any token).
		return true
	}
	return false
}

// ValidateActions validates every non-"*" action entry in the file, ensuring
// each parses as a valid pattern. This is the grant-time validation hook;
// callers (Task 2) invoke it when the .byn is presented for trust.
//
// Additional checks beyond pattern syntax:
//   - Empty strings are rejected (an empty action would always be unmatched
//     against any non-empty argv and serves no useful purpose).
//   - Any token that contains "{{" or "}}" but is NOT a valid whole-token
//     placeholder is rejected. This catches the silent-literal footgun:
//     "--flag={{uuid}}" would otherwise be treated as the literal string
//     "--flag={{uuid}}" rather than a flag with a typed placeholder, because
//     the token does not start and end with {{ / }}. Users who intend a
//     placeholder must split it into a separate token.
func (f File) ValidateActions() error {
	for _, action := range f.Exec.Actions {
		if action == "*" {
			continue
		}
		if action == "" {
			return fmt.Errorf("[exec.actions] entry must not be an empty string")
		}
		// Check for partial-brace tokens before full pattern parse so the
		// error message is specific.
		for _, tok := range strings.Fields(action) {
			if containsBraces(tok) && !isPlaceholder(tok) {
				return fmt.Errorf("[exec.actions] entry %q: token %q contains {{ or }} but is not a valid whole-token placeholder; split it or use a supported placeholder type", action, tok)
			}
		}
		if _, err := ParseActionPattern(action); err != nil {
			return fmt.Errorf("[exec.actions] entry %q: %w", action, err)
		}
	}
	return nil
}

// containsBraces reports whether s contains "{{" or "}}".
func containsBraces(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, "}}")
}

// aliasNameRe validates alias names: ^[A-Za-z0-9_][A-Za-z0-9_-]*$.
// Names must not start with '-', must not contain '/' or ':', and must not be
// the reserved token "--".
var aliasNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// ValidateAliases validates the [aliases] top-level table. Rules:
//   - Name must match ^[A-Za-z0-9_][A-Za-z0-9_-]*$ (no leading -, no / or :).
//   - Name must not be the reserved token "--".
//   - Value must be non-empty and strings.Fields(value) must be non-empty.
//   - Alias values must NOT contain placeholders (pattern lives in actions).
//
// Error messages name the offending alias.
func (f File) ValidateAliases() error {
	for name, value := range f.Aliases {
		// Validate name.
		if !aliasNameRe.MatchString(name) {
			return fmt.Errorf("[aliases] alias %q: name must match ^[A-Za-z0-9_][A-Za-z0-9_-]*$ (no leading -, no / or :)", name)
		}
		if name == "--" {
			return fmt.Errorf("[aliases] alias %q: \"--\" is reserved and may not be used as an alias name", name)
		}
		// Validate value.
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("[aliases] alias %q: value must be non-empty", name)
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return fmt.Errorf("[aliases] alias %q: value must contain at least one non-whitespace token", name)
		}
		// Alias values must not contain placeholders.
		for _, f := range fields {
			if isPlaceholder(f) {
				return fmt.Errorf("[aliases] alias %q: value %q contains placeholder %s; placeholders belong in [exec.actions] entries, not alias values", name, value, f)
			}
		}
	}
	return nil
}

// shellInterpreterNames is the set of base program names recognised as shell
// interpreters or scripting runtimes for the purpose of the footgun heuristic.
var shellInterpreterNames = map[string]bool{
	"sh":      true,
	"bash":    true,
	"zsh":     true,
	"dash":    true,
	"ksh":     true,
	"fish":    true,
	"python":  true,
	"python3": true,
	"node":    true,
	"perl":    true,
	"ruby":    true,
}

// ShellInterpreterWithPlaceholder reports whether p looks like a shell/script
// interpreter invocation that also has a typed placeholder. This is a
// heuristic for display warnings only — it is NOT a security gate. The check
// inspects only token[0]'s base name (via filepath.Base) against a fixed set
// of interpreter names.
//
// The heuristic is intentionally conservative: false negatives (missed
// interpreters) are preferable to false positives that alarm on legitimate
// uses such as `node --version`. The check uses exact base-name matching;
// version-suffixed names (e.g. "python3.11") that do not appear verbatim in
// shellInterpreterNames will NOT be recognized — no suffix stripping is done.
func ShellInterpreterWithPlaceholder(p Pattern) bool {
	if len(p.tokens) == 0 || !p.HasPlaceholders() {
		return false
	}
	tok0 := p.tokens[0]
	if tok0.kind != kindLiteral {
		return false
	}
	base := filepath.Base(tok0.literal)
	return shellInterpreterNames[base]
}
