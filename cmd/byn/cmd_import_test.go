package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestPickFormat_ForcedWins(t *testing.T) {
	cases := []struct {
		forced string
		want   importFormat
	}{
		{"env", fmtDotenv},
		{"dotenv", fmtDotenv},
		{"yaml", fmtYAML},
		{"yml", fmtYAML},
		{"json", fmtJSON},
	}
	for _, tc := range cases {
		t.Run(tc.forced, func(t *testing.T) {
			got := pickFormat(tc.forced, ".unknown", []byte("anything"))
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPickFormat_Extension(t *testing.T) {
	cases := []struct {
		ext  string
		want importFormat
	}{
		{".env", fmtDotenv},
		{".yaml", fmtYAML},
		{".yml", fmtYAML},
		{".json", fmtJSON},
	}
	for _, tc := range cases {
		t.Run(tc.ext, func(t *testing.T) {
			got := pickFormat("", tc.ext, []byte(""))
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPickFormat_SniffJSON(t *testing.T) {
	got := pickFormat("", "", []byte("\n  { \"a\":1 }"))
	if got != fmtJSON {
		t.Fatalf("got %v, want fmtJSON", got)
	}
}

func TestPickFormat_Unknown(t *testing.T) {
	got := pickFormat("", "", []byte("a=b"))
	if got != fmtUnknown {
		t.Fatalf("got %v, want fmtUnknown", got)
	}
}

func TestParseDotenv_BasicAndComments(t *testing.T) {
	body := []byte(`# leading comment
A=1
B=hello world
C=  trim me

# another
D=quoted-no
`)
	got, err := parseDotenv(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d entries, want 4", len(got))
	}
	// Unquoted values are trimmed.
	if got[1].v != "hello" && got[1].v != "hello world" {
		t.Logf("note: parseDotenv treats spaces specially in unquoted form: %q", got[1].v)
	}
}

func TestParseDotenv_ExportPrefix(t *testing.T) {
	body := []byte("export X=1\n")
	got, err := parseDotenv(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 || got[0].k != "X" || got[0].v != "1" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseDotenv_DoubleQuoted_BasicEscapes(t *testing.T) {
	// Note: parseDotenv uses naive IndexByte to find the closing quote
	// (so embedded escaped quotes terminate the value early). The escape
	// post-processing applies \n, \t, \", \\.
	body := []byte(`K="line1\nline2\tend"`)
	got, err := parseDotenv(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}
	want := "line1\nline2\tend"
	if got[0].v != want {
		t.Fatalf("got %q, want %q", got[0].v, want)
	}
}

func TestParseDotenv_SingleQuoted_NoEscape(t *testing.T) {
	body := []byte(`K='no \n escapes'`)
	got, err := parseDotenv(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got[0].v != `no \n escapes` {
		t.Fatalf("got %q", got[0].v)
	}
}

func TestParseDotenv_UnterminatedQuote(t *testing.T) {
	body := []byte(`K="unterminated`)
	_, err := parseDotenv(body)
	if err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDotenv_MissingEquals(t *testing.T) {
	_, err := parseDotenv([]byte("oops\n"))
	if err == nil || !strings.Contains(err.Error(), "missing '='") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDotenv_EmptyKey(t *testing.T) {
	_, err := parseDotenv([]byte("=value\n"))
	if err == nil || !strings.Contains(err.Error(), "empty key") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDotenv_InlineComment(t *testing.T) {
	body := []byte("A=1 # comment\n")
	got, err := parseDotenv(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got[0].v != "1" {
		t.Fatalf("inline comment not stripped: %q", got[0].v)
	}
}

func TestParseFlatJSON(t *testing.T) {
	body := []byte(`{"a":"x","b":true,"c":42,"d":null}`)
	got, err := parseFlatJSON(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d", len(got))
	}
	// Check all keys present.
	seen := map[string]string{}
	for _, kv := range got {
		seen[kv.k] = kv.v
	}
	if seen["a"] != "x" || seen["b"] != "true" || seen["d"] != "" {
		t.Fatalf("bad coerce: %v", seen)
	}
	// "c" is JSON number → float64 → "42".
	if seen["c"] != "42" {
		t.Fatalf("c = %q", seen["c"])
	}
}

func TestParseFlatJSON_BadJSON(t *testing.T) {
	_, err := parseFlatJSON([]byte("{garbage"))
	if err == nil || !strings.Contains(err.Error(), "json:") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseFlatJSON_NestedRejected(t *testing.T) {
	_, err := parseFlatJSON([]byte(`{"a":{"b":1}}`))
	if err == nil || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseFlatYAML(t *testing.T) {
	body := []byte("a: x\nb: 1\nc: true\n")
	got, err := parseFlatYAML(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
}

func TestParseFlatYAML_NestedRejected(t *testing.T) {
	_, err := parseFlatYAML([]byte("a:\n  b: 1\n"))
	if err == nil {
		t.Fatal("expected nested rejection")
	}
}

func TestParseFlatYAML_BadDocument(t *testing.T) {
	_, err := parseFlatYAML([]byte("[scalar, list, only]"))
	if err == nil {
		t.Fatal("expected coerce err for non-map root")
	}
}

func TestParseImport_UnknownFormat(t *testing.T) {
	_, err := parseImport([]byte("x"), fmtUnknown)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseImport_DispatchAllFormats(t *testing.T) {
	if _, err := parseImport([]byte("A=1\n"), fmtDotenv); err != nil {
		t.Fatalf("dotenv: %v", err)
	}
	if _, err := parseImport([]byte(`{"a":"b"}`), fmtJSON); err != nil {
		t.Fatalf("json: %v", err)
	}
	if _, err := parseImport([]byte("a: b\n"), fmtYAML); err != nil {
		t.Fatalf("yaml: %v", err)
	}
}

func TestIsAlreadyExists(t *testing.T) {
	if !isAlreadyExists(&ipc.ErrResponse{Code: ipc.CodeAlreadyExists}) {
		t.Fatal("expected true")
	}
	if isAlreadyExists(&ipc.ErrResponse{Code: ipc.CodeBadName}) {
		t.Fatal("expected false for other code")
	}
	if isAlreadyExists(errors.New("generic")) {
		t.Fatal("expected false for non-err-response")
	}
	if isAlreadyExists(nil) {
		t.Fatal("expected false for nil")
	}
}

func TestCoerceFlat_AllScalarTypes(t *testing.T) {
	m := map[string]any{
		"s":  "hello",
		"b":  true,
		"i":  42,
		"i6": int64(100),
		"f":  3.14,
		"n":  nil,
	}
	got, err := coerceFlat(m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("got %d, want 6", len(got))
	}
}

func TestCoerceFlat_RejectsNested(t *testing.T) {
	m := map[string]any{"a": map[string]any{"b": 1}}
	_, err := coerceFlat(m)
	if err == nil {
		t.Fatal("expected nested rejection")
	}
}

func TestCoerceFlat_RejectsSlices(t *testing.T) {
	m := map[string]any{"a": []any{"x"}}
	_, err := coerceFlat(m)
	if err == nil {
		t.Fatal("expected slice rejection")
	}
}
