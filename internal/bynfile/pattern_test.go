package bynfile

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseActionPattern — literal-only
// ---------------------------------------------------------------------------

func TestParseActionPatternLiteralOnly(t *testing.T) {
	p, err := ParseActionPattern("npm run start")
	require.NoError(t, err)
	assert.False(t, p.HasPlaceholders())
	assert.False(t, p.HasArgsTail())
	assert.Equal(t, "npm run start", p.String())
}

func TestParseActionPatternSingleLiteral(t *testing.T) {
	p, err := ParseActionPattern("make")
	require.NoError(t, err)
	assert.False(t, p.HasPlaceholders())
	assert.True(t, p.Match([]string{"make"}))
	assert.False(t, p.Match([]string{"make", "extra"}))
}

func TestParseActionPatternWildcardStarLiteral(t *testing.T) {
	// "*" is handled by ActionsAllowAll before reaching the pattern layer;
	// ParseActionPattern must accept it as a plain literal.
	p, err := ParseActionPattern("*")
	require.NoError(t, err)
	assert.False(t, p.HasPlaceholders(), "* is a literal token, not a placeholder")
	assert.True(t, p.Match([]string{"*"}))
	assert.False(t, p.Match([]string{"anything"}))
}

func TestParseActionPatternEmpty(t *testing.T) {
	p, err := ParseActionPattern("")
	require.NoError(t, err)
	assert.False(t, p.HasPlaceholders())
	assert.True(t, p.Match(nil))
	assert.True(t, p.Match([]string{}))
}

// ---------------------------------------------------------------------------
// UUID placeholder
// ---------------------------------------------------------------------------

var uuidValidCases = []string{
	"550e8400-e29b-41d4-a716-446655440000",
	"00000000-0000-0000-0000-000000000000",
	"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", // uppercase
	"A1B2C3D4-E5F6-A1B2-C3D4-E5F6A1B2C3D4", // mixed
}

var uuidInvalidCases = []string{
	"not-a-uuid",
	"550e8400-e29b-41d4-a716-44665544000",   // one digit short in last group
	"550e8400-e29b-41d4-a716-4466554400001", // one digit long in last group
	"550e8400-e29b-41d4-a716446655440000",   // missing a hyphen
	"",
	"550e8400-e29b-41d4-a716-44665544000g", // invalid hex char
}

func TestUUIDPlaceholderAccept(t *testing.T) {
	p, err := ParseActionPattern("cmd {{uuid}}")
	require.NoError(t, err)
	for _, v := range uuidValidCases {
		assert.True(t, p.Match([]string{"cmd", v}), "should accept UUID %q", v)
	}
}

func TestUUIDPlaceholderReject(t *testing.T) {
	p, err := ParseActionPattern("cmd {{uuid}}")
	require.NoError(t, err)
	for _, v := range uuidInvalidCases {
		assert.False(t, p.Match([]string{"cmd", v}), "should reject %q", v)
	}
}

// ---------------------------------------------------------------------------
// Int placeholder
// ---------------------------------------------------------------------------

func TestIntPlaceholderAccept(t *testing.T) {
	p, err := ParseActionPattern("set-port {{int}}")
	require.NoError(t, err)
	for _, v := range []string{"0", "42", "-1", "-999", "1234567890"} {
		assert.True(t, p.Match([]string{"set-port", v}), "should accept int %q", v)
	}
}

func TestIntPlaceholderReject(t *testing.T) {
	p, err := ParseActionPattern("set-port {{int}}")
	require.NoError(t, err)
	for _, v := range []string{"", "1.5", "1e3", "abc", "--1", "1-2"} {
		assert.False(t, p.Match([]string{"set-port", v}), "should reject %q", v)
	}
}

// ---------------------------------------------------------------------------
// Alnum placeholder
// ---------------------------------------------------------------------------

func TestAlnumPlaceholderAccept(t *testing.T) {
	p, err := ParseActionPattern("tag {{alnum}}")
	require.NoError(t, err)
	for _, v := range []string{"a", "Z", "abc123", "ABC", "A1B2C3"} {
		assert.True(t, p.Match([]string{"tag", v}), "should accept alnum %q", v)
	}
}

func TestAlnumPlaceholderReject(t *testing.T) {
	p, err := ParseActionPattern("tag {{alnum}}")
	require.NoError(t, err)
	for _, v := range []string{"", "abc-def", "abc_def", "abc.def", "abc!", "has space"} {
		assert.False(t, p.Match([]string{"tag", v}), "should reject %q", v)
	}
}

// ---------------------------------------------------------------------------
// Str placeholder (and {{*}} alias)
// ---------------------------------------------------------------------------

func TestStrPlaceholderAcceptsAnySingleToken(t *testing.T) {
	p, err := ParseActionPattern("do {{str}}")
	require.NoError(t, err)
	for _, v := range []string{"anything", "with-dashes", "123", "!@#$", "a"} {
		assert.True(t, p.Match([]string{"do", v}), "str should accept %q", v)
	}
}

func TestStrWildcardAliasAcceptsAnySingleToken(t *testing.T) {
	p, err := ParseActionPattern("do {{*}}")
	require.NoError(t, err)
	// {{*}} is an alias for {{str}}
	assert.True(t, p.Match([]string{"do", "anything"}))
	assert.False(t, p.Match([]string{"do"}))           // wrong arity
	assert.False(t, p.Match([]string{"do", "a", "b"})) // wrong arity
}

func TestStrHasPlaceholders(t *testing.T) {
	p, err := ParseActionPattern("cmd {{str}}")
	require.NoError(t, err)
	assert.True(t, p.HasPlaceholders())
}

// ---------------------------------------------------------------------------
// Path placeholder
// ---------------------------------------------------------------------------

func TestPathPlaceholderAcceptsNonNul(t *testing.T) {
	p, err := ParseActionPattern("open {{path}}")
	require.NoError(t, err)
	for _, v := range []string{"/etc/hosts", "./foo/bar", "relative", "C:\\Windows\\System32"} {
		assert.True(t, p.Match([]string{"open", v}), "path should accept %q", v)
	}
}

func TestPathPlaceholderRejectsNul(t *testing.T) {
	p, err := ParseActionPattern("open {{path}}")
	require.NoError(t, err)
	assert.False(t, p.Match([]string{"open", "foo\x00bar"}))
}

// ---------------------------------------------------------------------------
// URL placeholder
// ---------------------------------------------------------------------------

func TestURLPlaceholderAcceptsAbsoluteURL(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url}}")
	require.NoError(t, err)
	for _, v := range []string{
		"https://example.com",
		"http://example.com/path?q=1",
		"ftp://files.example.com",
	} {
		assert.True(t, p.Match([]string{"fetch", v}), "url should accept %q", v)
	}
}

func TestURLPlaceholderRejectsRelativeAndBare(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url}}")
	require.NoError(t, err)
	for _, v := range []string{
		"example.com",
		"/path/only",
		"not a url",
		"",
	} {
		assert.False(t, p.Match([]string{"fetch", v}), "url should reject %q", v)
	}
}

func TestURLConstraintHost(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url:host=www.example.com}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"fetch", "https://www.example.com/path"}))
	assert.False(t, p.Match([]string{"fetch", "https://other.example.com/path"}))
	assert.False(t, p.Match([]string{"fetch", "https://example.com/path"}))
}

func TestURLConstraintScheme(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url:scheme=https}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"fetch", "https://example.com"}))
	assert.False(t, p.Match([]string{"fetch", "http://example.com"}))
	assert.False(t, p.Match([]string{"fetch", "ftp://example.com"}))
}

func TestURLConstraintHostAndScheme(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url:scheme=https,host=www.example.com}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"fetch", "https://www.example.com/foo"}))
	assert.False(t, p.Match([]string{"fetch", "http://www.example.com/foo"}))
	assert.False(t, p.Match([]string{"fetch", "https://other.example.com/foo"}))
}

func TestURLConstraintNonMatchingHost(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url:host=api.internal.com}}")
	require.NoError(t, err)
	assert.False(t, p.Match([]string{"fetch", "https://attacker.com"}))
	assert.False(t, p.Match([]string{"fetch", "https://api.internal.com.evil.com"}))
}

func TestURLBadConstraintKey(t *testing.T) {
	_, err := ParseActionPattern("fetch {{url:port=8080}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

// ---------------------------------------------------------------------------
// Re placeholder
// ---------------------------------------------------------------------------

func TestRePlaceholderAccept(t *testing.T) {
	p, err := ParseActionPattern("cmd {{re:[0-9]{4}}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"cmd", "1234"}))
	assert.True(t, p.Match([]string{"cmd", "0000"}))
}

func TestRePlaceholderReject(t *testing.T) {
	p, err := ParseActionPattern("cmd {{re:[0-9]{4}}}")
	require.NoError(t, err)
	assert.False(t, p.Match([]string{"cmd", "123"}))   // too short
	assert.False(t, p.Match([]string{"cmd", "12345"})) // too long
	assert.False(t, p.Match([]string{"cmd", "abcd"}))  // wrong class
}

func TestReAnchoring(t *testing.T) {
	// re:a must NOT match "xa" — the pattern is anchored ^(?:a)$
	p, err := ParseActionPattern("cmd {{re:a}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"cmd", "a"}))
	assert.False(t, p.Match([]string{"cmd", "xa"}))
	assert.False(t, p.Match([]string{"cmd", "ax"}))
	assert.False(t, p.Match([]string{"cmd", "xax"}))
}

func TestReCompileFailure(t *testing.T) {
	// An invalid RE2 pattern must be rejected at parse time.
	_, err := ParseActionPattern("cmd {{re:[invalid}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re:")
}

func TestReComplexPattern(t *testing.T) {
	p, err := ParseActionPattern("cmd {{re:(foo|bar)-(baz|qux)}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"cmd", "foo-baz"}))
	assert.True(t, p.Match([]string{"cmd", "bar-qux"}))
	assert.False(t, p.Match([]string{"cmd", "foo-foo"}))
	assert.False(t, p.Match([]string{"cmd", "baz-bar"}))
}

// ---------------------------------------------------------------------------
// {{args}} placeholder
// ---------------------------------------------------------------------------

func TestArgsFinalToken(t *testing.T) {
	p, err := ParseActionPattern("git commit {{args}}")
	require.NoError(t, err)
	assert.True(t, p.HasArgsTail())
	// {{args}} absorbs zero tokens
	assert.True(t, p.Match([]string{"git", "commit"}))
	// {{args}} absorbs one token
	assert.True(t, p.Match([]string{"git", "commit", "-m"}))
	// {{args}} absorbs many tokens
	assert.True(t, p.Match([]string{"git", "commit", "-m", "msg", "--amend"}))
}

func TestArgsZeroRemaining(t *testing.T) {
	p, err := ParseActionPattern("run {{args}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"run"})) // zero additional tokens
}

func TestArgsMidPatternIsError(t *testing.T) {
	// {{args}} in a non-final position must be a validation error.
	_, err := ParseActionPattern("cmd {{args}} extra")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "{{args}}")
	assert.Contains(t, err.Error(), "final")
}

func TestArgsMidPatternTwoPlaceholders(t *testing.T) {
	_, err := ParseActionPattern("{{args}} {{str}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "{{args}}")
}

func TestArgsOnlyToken(t *testing.T) {
	// A pattern of just {{args}} — must parse and match anything.
	p, err := ParseActionPattern("{{args}}")
	require.NoError(t, err)
	assert.True(t, p.HasArgsTail())
	assert.True(t, p.Match(nil))
	assert.True(t, p.Match([]string{}))
	assert.True(t, p.Match([]string{"a", "b", "c"}))
}

// ---------------------------------------------------------------------------
// ValidateActions rejection tests (Part A.1 — carried review fixes)
// ---------------------------------------------------------------------------

// TestValidateActionsEmptyStringRejected: an empty-string action entry must
// be rejected (ValidateActions must not accept "").
func TestValidateActionsEmptyStringRejected(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{""}
	err := f.ValidateActions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[exec.actions]")
}

// TestValidateActionsPartialBraceTokenRejected: a token that contains {{...}}
// but is not a whole-token placeholder must be rejected with the token named.
// "--flag={{uuid}}" is the canonical footgun case.
func TestValidateActionsPartialBraceTokenRejected(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{"cmd --flag={{uuid}}"}
	err := f.ValidateActions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[exec.actions]")
	assert.Contains(t, err.Error(), "--flag={{uuid}}")
}

// TestValidateActionsSpaceSplitURLConstraintRejected: "{{url:host=x.com, scheme=https}}"
// — the space after the comma causes the token to be split into two fields by
// strings.Fields, producing "{{url:host=x.com," (partial brace) and
// "scheme=https}}" (partial brace). Both partial tokens must be caught.
func TestValidateActionsSpaceSplitURLConstraintRejected(t *testing.T) {
	f := File{}
	// Space after comma → strings.Fields splits into two bad tokens.
	f.Exec.Actions = EnvList{"fetch {{url:host=x.com, scheme=https}}"}
	err := f.ValidateActions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[exec.actions]")
}

// ---------------------------------------------------------------------------
// Unknown type — validation error
// ---------------------------------------------------------------------------

func TestUnknownPlaceholderType(t *testing.T) {
	_, err := ParseActionPattern("cmd {{bogus}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
	assert.Contains(t, err.Error(), "unknown placeholder")
}

func TestUnknownPlaceholderTypeFloat(t *testing.T) {
	_, err := ParseActionPattern("cmd {{float}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "float")
}

// ---------------------------------------------------------------------------
// Mixed literal + placeholder
// ---------------------------------------------------------------------------

// Verbatim scraper example from the spec.
func TestScraperPatternMatchesScrapeWithUUIDAndURL(t *testing.T) {
	p, err := ParseActionPattern("npm run scrape --website-id {{uuid}} --website-url {{url:host=www.website.com}}")
	require.NoError(t, err)
	assert.True(t, p.HasPlaceholders())

	// The VERBATIM argv from the spec — must match.
	match := p.Match([]string{
		"npm", "run", "scrape",
		"--website-id", "550e8400-e29b-41d4-a716-446655440000",
		"--website-url", "https://www.website.com/abc/?and=123",
	})
	assert.True(t, match, "verbatim scraper argv should match")
}

func TestScraperPatternRejectsWrongHost(t *testing.T) {
	p, err := ParseActionPattern("npm run scrape --website-id {{uuid}} --website-url {{url:host=www.website.com}}")
	require.NoError(t, err)

	// Wrong host — must NOT match.
	reject := p.Match([]string{
		"npm", "run", "scrape",
		"--website-id", "550e8400-e29b-41d4-a716-446655440000",
		"--website-url", "https://www.evil.com/abc/?and=123",
	})
	assert.False(t, reject, "wrong host should not match")
}

func TestScraperPatternRejectsWrongUUID(t *testing.T) {
	p, err := ParseActionPattern("npm run scrape --website-id {{uuid}} --website-url {{url:host=www.website.com}}")
	require.NoError(t, err)

	reject := p.Match([]string{
		"npm", "run", "scrape",
		"--website-id", "not-a-uuid",
		"--website-url", "https://www.website.com/",
	})
	assert.False(t, reject)
}

func TestMixedLiteralsAndPlaceholders(t *testing.T) {
	p, err := ParseActionPattern("deploy --env {{alnum}} --count {{int}} {{args}}")
	require.NoError(t, err)
	assert.True(t, p.HasPlaceholders())
	assert.True(t, p.HasArgsTail())

	assert.True(t, p.Match([]string{"deploy", "--env", "production", "--count", "3"}))
	assert.True(t, p.Match([]string{"deploy", "--env", "production", "--count", "3", "--dry-run"}))
	assert.False(t, p.Match([]string{"deploy", "--env", "prod-123", "--count", "3"})) // alnum rejects dash
	assert.False(t, p.Match([]string{"deploy", "--env", "production", "--count", "x"}))
}

// ---------------------------------------------------------------------------
// ValidateActions
// ---------------------------------------------------------------------------

func TestValidateActionsAllValid(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{
		"npm run start",
		"make test",
		"deploy --env {{alnum}}",
		"*",
	}
	assert.NoError(t, f.ValidateActions())
}

func TestValidateActionsInvalidPattern(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{"cmd {{badtype}}"}
	err := f.ValidateActions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[exec.actions]")
	assert.Contains(t, err.Error(), "badtype")
}

func TestValidateActionsArgsMidPattern(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{"cmd {{args}} extra"}
	err := f.ValidateActions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[exec.actions]")
}

func TestValidateActionsEmpty(t *testing.T) {
	f := File{}
	assert.NoError(t, f.ValidateActions())
}

func TestValidateActionsWildcardSkipped(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{"*"}
	assert.NoError(t, f.ValidateActions())
}

// ---------------------------------------------------------------------------
// Alias parsing via TOML
// ---------------------------------------------------------------------------

func TestParseAliasesFromTOML(t *testing.T) {
	// Top-level [aliases] table (schema convention: collections are top-level).
	const body = `
[exec]
actions = ["npm run {{str}}"]

[aliases]
start = "npm run start"
test-all = "npm run test"
`
	f, err := Parse([]byte(body))
	require.NoError(t, err)
	require.NotNil(t, f.Aliases)
	assert.Equal(t, "npm run start", f.Aliases["start"])
	assert.Equal(t, "npm run test", f.Aliases["test-all"])
}

func TestParseAliasesUnderExec_Fails(t *testing.T) {
	// [exec.aliases] was the old nested location; after the schema relocation,
	// strict TOML rejects it as an unknown key under [exec].
	// Pin this regression: [exec.aliases] must FAIL after the move to [aliases].
	const body = `
[exec]
actions = ["make test"]
[exec.aliases]
test = "npm test"
`
	_, err := Parse([]byte(body))
	require.Error(t, err, "[exec.aliases] must fail — aliases moved to top-level [aliases]")
}

// ---------------------------------------------------------------------------
// ValidateAliases
// ---------------------------------------------------------------------------

func TestValidateAliasesValidNames(t *testing.T) {
	validNames := []string{
		"start",
		"test_all",
		"A1",
		"my-command",
		"_internal",
		"a0-b_c",
	}
	for _, name := range validNames {
		f := File{}
		f.Aliases = map[string]string{name: "cmd arg"}
		assert.NoError(t, f.ValidateAliases(), "name %q should be valid", name)
	}
}

func TestValidateAliasesInvalidNames(t *testing.T) {
	invalidNames := []string{
		"-starts-with-dash",
		"has/slash",
		"has:colon",
		"has space",
		"",
		"has.dot",
		"has!bang",
	}
	for _, name := range invalidNames {
		f := File{}
		f.Aliases = map[string]string{name: "cmd arg"}
		err := f.ValidateAliases()
		require.Error(t, err, "name %q should be invalid", name)
		if name != "" {
			assert.Contains(t, err.Error(), name, "error should mention offending alias")
		}
		assert.Contains(t, err.Error(), "[aliases]")
	}
}

func TestValidateAliasesReservedDoubleDash(t *testing.T) {
	// "--" is the reserved alias name and must be rejected.
	// Note: "--" starts with "-" so it already fails the name regex check;
	// the reserved name check is belt-and-suspenders for the exact "--" case.
	f := File{}
	f.Aliases = map[string]string{"--": "cmd"}
	err := f.ValidateAliases()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[aliases]")
}

func TestValidateAliasesEmptyValue(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"deploy": ""}
	err := f.ValidateAliases()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deploy")
	assert.Contains(t, err.Error(), "[aliases]")
}

func TestValidateAliasesWhitespaceOnlyValue(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"deploy": "   "}
	err := f.ValidateAliases()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deploy")
}

func TestValidateAliasesPlaceholderInValueRejected(t *testing.T) {
	// Placeholders belong in [exec.actions], not alias values.
	f := File{}
	f.Aliases = map[string]string{"run": "npm run {{str}}"}
	err := f.ValidateAliases()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run")
	assert.Contains(t, err.Error(), "placeholder")
	assert.Contains(t, err.Error(), "[aliases]")
}

func TestValidateAliasesAllPlaceholderTypesRejected(t *testing.T) {
	placeholders := []string{
		"{{uuid}}", "{{int}}", "{{alnum}}", "{{str}}", "{{*}}",
		"{{path}}", "{{url}}", "{{args}}",
	}
	for _, ph := range placeholders {
		f := File{}
		f.Aliases = map[string]string{"cmd": "prefix " + ph}
		err := f.ValidateAliases()
		require.Error(t, err, "placeholder %q in alias value should be rejected", ph)
		assert.Contains(t, err.Error(), "placeholder")
	}
}

func TestValidateAliasesNilReturnsNil(t *testing.T) {
	f := File{}
	assert.NoError(t, f.ValidateAliases())
}

func TestValidateAliasesMultiTokenValue(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"build": "go build ./..."}
	assert.NoError(t, f.ValidateAliases())
}

// ---------------------------------------------------------------------------
// ShellInterpreterWithPlaceholder
// ---------------------------------------------------------------------------

func TestShellInterpreterWithPlaceholder(t *testing.T) {
	interpreters := []string{
		"sh", "bash", "zsh", "dash", "ksh", "fish",
		"python", "python3", "node", "perl", "ruby",
	}
	for _, interp := range interpreters {
		p, err := ParseActionPattern(interp + " {{str}}")
		require.NoError(t, err)
		assert.True(t, ShellInterpreterWithPlaceholder(p), "%s with placeholder should be flagged", interp)
	}
}

func TestShellInterpreterWithPlaceholderAbsPath(t *testing.T) {
	// Absolute path to the interpreter — filepath.Base normalises it.
	p, err := ParseActionPattern("/usr/bin/bash {{str}}")
	require.NoError(t, err)
	assert.True(t, ShellInterpreterWithPlaceholder(p))
}

func TestShellInterpreterNoPlaceholder(t *testing.T) {
	p, err := ParseActionPattern("bash script.sh")
	require.NoError(t, err)
	assert.False(t, ShellInterpreterWithPlaceholder(p), "no placeholder → no warning")
}

func TestShellInterpreterNonInterpreterWithPlaceholder(t *testing.T) {
	p, err := ParseActionPattern("kubectl get {{str}}")
	require.NoError(t, err)
	assert.False(t, ShellInterpreterWithPlaceholder(p))
}

func TestShellInterpreterEmptyPattern(t *testing.T) {
	p, err := ParseActionPattern("")
	require.NoError(t, err)
	assert.False(t, ShellInterpreterWithPlaceholder(p))
}

func TestShellInterpreterFirstTokenPlaceholder(t *testing.T) {
	// If token[0] is itself a placeholder, not a literal interpreter name.
	p, err := ParseActionPattern("{{str}} script.sh")
	require.NoError(t, err)
	assert.False(t, ShellInterpreterWithPlaceholder(p))
}

// ---------------------------------------------------------------------------
// Match arity edge cases
// ---------------------------------------------------------------------------

func TestMatchArityTooFew(t *testing.T) {
	p, err := ParseActionPattern("a b c")
	require.NoError(t, err)
	assert.False(t, p.Match([]string{"a", "b"}))
}

func TestMatchArityTooMany(t *testing.T) {
	p, err := ParseActionPattern("a b")
	require.NoError(t, err)
	assert.False(t, p.Match([]string{"a", "b", "c"}))
}

func TestMatchArityExact(t *testing.T) {
	p, err := ParseActionPattern("a b c")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"a", "b", "c"}))
}

// ---------------------------------------------------------------------------
// Property test: random mutations should not accidentally match a strict pattern
// ---------------------------------------------------------------------------

// mutateArgv returns a copy of argv with one token replaced by a random string.
func mutateArgv(argv []string, rng *rand.Rand) []string {
	if len(argv) == 0 {
		return argv
	}
	out := make([]string, len(argv))
	copy(out, argv)
	idx := rng.Intn(len(argv))
	// Generate a random token that is different from the original.
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789-_"
	length := rng.Intn(8) + 1
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rng.Intn(len(charset))]
	}
	out[idx] = string(b)
	return out
}

func TestPropertyRandomMutationsDoNotMatchStrictPattern(t *testing.T) {
	// A strict pattern with no wildcards; mutations to literal tokens should
	// almost always fail. We run 500 iterations.
	p, err := ParseActionPattern("npm run build --env production")
	require.NoError(t, err)

	correctArgv := []string{"npm", "run", "build", "--env", "production"}
	rng := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic seed for test

	mismatches := 0
	for i := 0; i < 500; i++ {
		mutated := mutateArgv(correctArgv, rng)
		// Check if it's still the original (unlikely but possible).
		same := true
		for j, v := range mutated {
			if v != correctArgv[j] {
				same = false
				break
			}
		}
		if same {
			continue
		}
		if p.Match(mutated) {
			mismatches++
		}
	}
	assert.Zero(t, mismatches, "random mutations should not match the strict literal pattern")
}

func TestPropertyRandomArgvDoNotMatchPlaceholderPattern(t *testing.T) {
	// Pattern requires specific literals and a UUID; random junk for the UUID
	// slot should fail most of the time. We check for false positives in the
	// non-UUID slot (the literal "deploy").
	p, err := ParseActionPattern("deploy --id {{uuid}}")
	require.NoError(t, err)

	rng := rand.New(rand.NewSource(99)) //nolint:gosec // deterministic seed for test

	const charset = "xyz!@#0-9a-f"
	falsepositives := 0
	for i := 0; i < 500; i++ {
		// Generate a random non-UUID string.
		length := rng.Intn(10) + 1
		b := make([]byte, length)
		for j := range b {
			b[j] = charset[rng.Intn(len(charset))]
		}
		argv := []string{"deploy", "--id", string(b)}
		if p.Match(argv) {
			falsepositives++
		}
	}
	// We expect all to fail; a valid UUID has an astronomically low chance of
	// occurring in random short strings.
	assert.Zero(t, falsepositives, "random short strings should not pass UUID validation")
}

// ---------------------------------------------------------------------------
// Integration: TOML round-trip with ValidateActions + ValidateAliases
// ---------------------------------------------------------------------------

func TestTOMLRoundTripWithValidation(t *testing.T) {
	const body = `
[exec]
env = ["DB_URL"]
actions = [
  "npm run scrape --website-id {{uuid}} --website-url {{url:host=www.website.com}}",
  "make test",
  "*",
]

[aliases]
scrape = "npm run scrape"
build = "go build ./..."
`
	f, err := Parse([]byte(body))
	require.NoError(t, err)

	assert.NoError(t, f.ValidateActions())
	assert.NoError(t, f.ValidateAliases())

	assert.Equal(t, "npm run scrape", f.Aliases["scrape"])
	assert.Equal(t, "go build ./...", f.Aliases["build"])
}

func TestTOMLAliasesUnknownKeyFails(t *testing.T) {
	// Strict TOML: unknown keys under [exec] should fail.
	_, err := Parse([]byte("[exec]\nbogusfield = 1\n"))
	require.Error(t, err)
}

func TestAliasesAbsentDoesNotFail(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = [\"A\"]\n"))
	require.NoError(t, err)
	assert.Nil(t, f.Aliases)
	assert.NoError(t, f.ValidateAliases())
}

// ---------------------------------------------------------------------------
// Additional edge cases for URL placeholder
// ---------------------------------------------------------------------------

func TestURLPlaceholderPortInHost(t *testing.T) {
	// When no host constraint, URL with port should pass.
	p, err := ParseActionPattern("fetch {{url}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"fetch", "http://localhost:8080/path"}))
}

func TestURLConstraintHostWithPort(t *testing.T) {
	// host constraint matches u.Hostname() (without port).
	p, err := ParseActionPattern("fetch {{url:host=localhost}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"fetch", "http://localhost:8080/path"}))
	assert.False(t, p.Match([]string{"fetch", "http://other:8080/path"}))
}

func TestURLSchemeConstraintCaseSensitive(t *testing.T) {
	p, err := ParseActionPattern("fetch {{url:scheme=https}}")
	require.NoError(t, err)
	// url.Parse lowercases the scheme, so "HTTPS" is still "https" after parse.
	// This tests that our constraint check is against the parsed scheme.
	assert.True(t, p.Match([]string{"fetch", "https://example.com"}))
}

// ---------------------------------------------------------------------------
// HasArgsTail / HasPlaceholders combination
// ---------------------------------------------------------------------------

func TestPatternOnlyArgs(t *testing.T) {
	p, err := ParseActionPattern("{{args}}")
	require.NoError(t, err)
	assert.True(t, p.HasPlaceholders())
	assert.True(t, p.HasArgsTail())
}

func TestLiteralPatternNeitherFlag(t *testing.T) {
	p, err := ParseActionPattern("a b c")
	require.NoError(t, err)
	assert.False(t, p.HasPlaceholders())
	assert.False(t, p.HasArgsTail())
}

// ---------------------------------------------------------------------------
// Str placeholder does not match extra tokens (arity enforcement)
// ---------------------------------------------------------------------------

func TestStrDoesNotAbsorbExtraTokens(t *testing.T) {
	p, err := ParseActionPattern("cmd {{str}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"cmd", "one"}))
	assert.False(t, p.Match([]string{"cmd", "one", "two"}))
}

// ---------------------------------------------------------------------------
// String() method
// ---------------------------------------------------------------------------

func TestPatternStringReturnsOriginal(t *testing.T) {
	action := "npm run scrape --website-id {{uuid}}"
	p, err := ParseActionPattern(action)
	require.NoError(t, err)
	assert.Equal(t, action, p.String())
}

// ---------------------------------------------------------------------------
// Re placeholder with whitespace in token — must not match across fields
// ---------------------------------------------------------------------------

func TestReDoesNotMatchAcrossFields(t *testing.T) {
	// A pattern designed to match "hello world" as a single token should fail
	// because fields are split; "hello world" would never appear as one argv element
	// when the pattern was parsed (each is its own token).
	// This tests that anchoring + per-token matching is correct.
	p, err := ParseActionPattern("cmd {{re:hello}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"cmd", "hello"}))
	assert.False(t, p.Match([]string{"cmd", "hello", "world"}))
}

// ---------------------------------------------------------------------------
// Alias name: single character is valid
// ---------------------------------------------------------------------------

func TestAliasNameSingleCharValid(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"a": "cmd"}
	assert.NoError(t, f.ValidateAliases())
}

// ---------------------------------------------------------------------------
// Ensure {{args}} with preceding placeholder works
// ---------------------------------------------------------------------------

func TestArgsWithPrecedingPlaceholder(t *testing.T) {
	p, err := ParseActionPattern("run {{str}} {{args}}")
	require.NoError(t, err)
	assert.True(t, p.HasArgsTail())
	assert.True(t, p.Match([]string{"run", "script"}))
	assert.True(t, p.Match([]string{"run", "script", "--verbose", "--debug"}))
	assert.False(t, p.Match([]string{"run"})) // missing {{str}} token
}

// ---------------------------------------------------------------------------
// Multiple adjacent placeholders
// ---------------------------------------------------------------------------

func TestMultiplePlaceholders(t *testing.T) {
	p, err := ParseActionPattern("{{str}} {{int}} {{uuid}}")
	require.NoError(t, err)
	assert.True(t, p.Match([]string{"anything", "42", "550e8400-e29b-41d4-a716-446655440000"}))
	assert.False(t, p.Match([]string{"anything", "notint", "550e8400-e29b-41d4-a716-446655440000"}))
}

// ---------------------------------------------------------------------------
// Validate that isPlaceholder helper is correct
// ---------------------------------------------------------------------------

func TestIsPlaceholderEdgeCases(t *testing.T) {
	assert.True(t, isPlaceholder("{{uuid}}"))
	assert.True(t, isPlaceholder("{{}}"))
	assert.False(t, isPlaceholder("{uuid}"))  // only one brace level
	assert.False(t, isPlaceholder("{{uuid}")) // missing closing
	assert.False(t, isPlaceholder("uuid}}"))  // missing opening
	assert.False(t, isPlaceholder("plain"))
	assert.False(t, isPlaceholder(""))
}

// ---------------------------------------------------------------------------
// ValidateActions error surfaces the entry value
// ---------------------------------------------------------------------------

func TestValidateActionsErrorMentionsEntry(t *testing.T) {
	f := File{}
	f.Exec.Actions = EnvList{"cmd {{badtype}}"}
	err := f.ValidateActions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cmd {{badtype}}")
}

// Ensure that strings.Fields tokenisation is consistent: multi-space is same as single space.
func TestPatternMultiSpaceNormalized(t *testing.T) {
	p1, err := ParseActionPattern("a b c")
	require.NoError(t, err)
	p2, err := ParseActionPattern("a  b  c") // double spaces
	require.NoError(t, err)
	// Both should produce the same match behaviour.
	assert.Equal(t, p1.Match([]string{"a", "b", "c"}), p2.Match([]string{"a", "b", "c"}))
}

// ValidateAliases with a placeholder token that looks like a URL constraint.
func TestAliasValueURLPlaceholderRejected(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"fetch": "curl {{url:scheme=https}}"}
	err := f.ValidateAliases()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "placeholder")
}

// Re pattern that would match substrings without anchoring — ensure anchoring prevents it.
func TestReAnchoringPreventsSubstringMatch(t *testing.T) {
	// Without anchoring, ".*hello.*" would match "say hello world".
	// Our anchoring ensures only "hello" matches the pattern {{re:hello}}.
	p, err := ParseActionPattern("msg {{re:hello}}")
	require.NoError(t, err)
	assert.False(t, p.Match([]string{"msg", "say hello world"}))
	assert.True(t, p.Match([]string{"msg", "hello"}))
}

// Placeholder inside a longer non-brace string should be treated as a literal.
func TestNonBracedPlaceholderIsLiteral(t *testing.T) {
	p, err := ParseActionPattern("cmd $UUID")
	require.NoError(t, err)
	assert.False(t, p.HasPlaceholders())
	assert.True(t, p.Match([]string{"cmd", "$UUID"}))
	assert.False(t, p.Match([]string{"cmd", "550e8400-e29b-41d4-a716-446655440000"}))
}

// Empty inner placeholder {{}} — should fail with unknown placeholder type.
func TestEmptyPlaceholderType(t *testing.T) {
	_, err := ParseActionPattern("cmd {{}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown placeholder")
}

// Alias name with only underscores is valid.
func TestAliasNameUnderscoreOnly(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"_": "cmd"}
	assert.NoError(t, f.ValidateAliases())
}

// Alias name starting with digit is invalid (must start with [A-Za-z0-9_] but
// the regex ^[A-Za-z0-9_][A-Za-z0-9_-]*$ allows starting with a digit).
func TestAliasNameStartingWithDigitValid(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"1build": "cmd"}
	// Per the spec regex: ^[A-Za-z0-9_][A-Za-z0-9_-]*$ — digits are allowed at position 0.
	assert.NoError(t, f.ValidateAliases())
}

// Alias name with leading dash invalid.
func TestAliasNameLeadingDashInvalid(t *testing.T) {
	f := File{}
	f.Aliases = map[string]string{"-build": "cmd"}
	err := f.ValidateAliases()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-build")
}
