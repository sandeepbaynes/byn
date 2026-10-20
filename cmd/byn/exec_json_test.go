package main

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestStripExecJSON(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		wantArgs []string
		wantJSON bool
	}{
		{name: "absent", in: []string{"--", "echo", "hi"}, wantArgs: []string{"--", "echo", "hi"}},
		{name: "byn's own flag", in: []string{"--json", "--", "echo"}, wantArgs: []string{"--", "echo"}, wantJSON: true},
		{
			// The child's own --json must survive: byn's flags end at "--".
			name:     "after the separator it belongs to the child",
			in:       []string{"--", "mytool", "--json"},
			wantArgs: []string{"--", "mytool", "--json"},
		},
		{
			name:     "after an alias name it belongs to the child",
			in:       []string{"build", "--json"},
			wantArgs: []string{"build", "--json"},
		},
		{
			name:     "both: byn's before, the child's after",
			in:       []string{"--json", "--", "mytool", "--json"},
			wantArgs: []string{"--", "mytool", "--json"},
			wantJSON: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotJSON := stripExecJSON(tc.in)
			if gotJSON != tc.wantJSON {
				t.Errorf("json = %v, want %v", gotJSON, tc.wantJSON)
			}
			if !reflect.DeepEqual(got, tc.wantArgs) {
				t.Errorf("args = %v, want %v", got, tc.wantArgs)
			}
		})
	}
}

// The point of the flag: an id an agent can read from a field.
func TestExecApprovalJSONCarriesTheId(t *testing.T) {
	err := &ipc.ErrResponse{
		Code:    ipc.CodeApprovalPending,
		Message: "echo hi is not pinned in /p/.byn [exec] actions — approval abc123 is waiting",
		Recover: "approve it with: byn approve abc123",
		Details: map[string]string{
			"approval_id": "abc123",
			"kind":        "action_unpinned",
			"byn":         "/p/.byn",
			"command":     "echo hi",
			"expires_at":  "1787923798",
		},
	}
	out := captureStdout(t, func() { execApprovalJSON(os.Stdout, err, 75) })

	var got map[string]any
	if uerr := json.Unmarshal([]byte(out), &got); uerr != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", uerr, out)
	}
	if got["approval_id"] != "abc123" {
		t.Errorf("approval_id = %v, want abc123 — this is the field agents read instead of the prose", got["approval_id"])
	}
	if got["status"] != string(ipc.CodeApprovalPending) {
		t.Errorf("status = %v, want approval_pending", got["status"])
	}
	if got["exit"] != float64(75) {
		t.Errorf("exit = %v, want 75", got["exit"])
	}
	// expires_at is a number, not a string, so a caller can compare it.
	if _, ok := got["expires_at"].(float64); !ok {
		t.Errorf("expires_at = %#v, want a number", got["expires_at"])
	}
	if got["command"] != "echo hi" {
		t.Errorf("command = %v, want \"echo hi\"", got["command"])
	}
}

// An older daemon sends no details. The output must still be valid JSON with a
// status, rather than nothing at all.
func TestExecApprovalJSONWithoutDetails(t *testing.T) {
	err := &ipc.ErrResponse{Code: ipc.CodeApprovalPending, Message: "waiting"}
	out := captureStdout(t, func() { execApprovalJSON(os.Stdout, err, 75) })
	var got map[string]any
	if uerr := json.Unmarshal([]byte(out), &got); uerr != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", uerr, out)
	}
	if got["status"] != string(ipc.CodeApprovalPending) {
		t.Errorf("status = %v, want approval_pending", got["status"])
	}
	if got["message"] != "waiting" {
		t.Errorf("message = %v, want the daemon's text as a fallback", got["message"])
	}
}

// A timestamp must be a number whichever command emitted it. The details map is
// string-keyed on the wire, and passing it through verbatim gave denied_at a
// different type in the wall's output than in the pre-flight's — enough to break
// a consumer that compares it to a clock.
func TestExecErrorJSONTimestampsAreNumbers(t *testing.T) {
	for _, key := range []string{"denied_at", "expires_at"} {
		err := &ipc.ErrResponse{
			Code:    ipc.CodeTrustDenied,
			Message: "refused",
			Details: map[string]string{key: "1787916016", "reason": "nope"},
		}
		out := captureStdout(t, func() { execWallJSON(os.Stdout, err, 3) })
		var got map[string]any
		if uerr := json.Unmarshal([]byte(out), &got); uerr != nil {
			t.Fatalf("not JSON: %v\n%s", uerr, out)
		}
		if _, ok := got[key].(float64); !ok {
			t.Errorf("%s = %#v, want a number", key, got[key])
		}
		if got["reason"] != "nope" {
			t.Errorf("reason = %v, want the string through unchanged", got["reason"])
		}
	}
}

// --reason is byn's flag, but only before the child's argv begins. A child that
// has a --reason of its own must still receive it.
func TestStripExecReason_StopsAtTheChild(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     []string
		want   []string
		reason string
	}{
		{"separate value", []string{"--reason", "for the auth work", "--", "make", "dev"},
			[]string{"--", "make", "dev"}, "for the auth work"},
		{"equals form", []string{"--reason=deploying", "--", "make"},
			[]string{"--", "make"}, "deploying"},
		{"absent", []string{"--", "make"}, []string{"--", "make"}, ""},
		{"belongs to the child", []string{"--", "mytool", "--reason", "theirs"},
			[]string{"--", "mytool", "--reason", "theirs"}, ""},
		{"child of an alias form", []string{"dev", "--reason", "theirs"},
			[]string{"dev", "--reason", "theirs"}, ""},
		{"dangling value", []string{"--reason"}, []string{"--reason"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := stripExecReason(tc.in)
			if reason != tc.reason {
				t.Errorf("reason = %q, want %q", reason, tc.reason)
			}
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Errorf("args = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every exec flag is found wherever it sits among byn's flags, including after
// one that takes a value. Each pass used to stop at the first bare token, so a
// flag behind `--reason "why"` was never seen by the passes that ran first.
func TestExecFlags_SeenAfterAValueFlag(t *testing.T) {
	args := []string{"--reason", "why", "--inspect", "9230", "--wait-approval", "1m",
		"--json", "--dry-run", "--force-ask", "--once", "--no-privsep", "--", "cmd", "--json"}
	args, noPrivsep := stripNoPrivsep(args)
	args, _, hasWait := stripWaitApproval(args)
	args, jsonOut := stripExecJSON(args)
	args, dryRun := stripExecDryRun(args)
	args, forceAsk := stripExecForceAsk(args)
	args, reason := stripExecReason(args)
	args, askOnce := stripExecAskOnce(args)
	args, _, inspect, hasInspect := stripInspect(args)
	if !noPrivsep || !hasWait || !jsonOut || !dryRun || !forceAsk || !askOnce || !hasInspect {
		t.Errorf("missed a flag: privsep=%v wait=%v json=%v dry=%v force=%v once=%v inspect=%v",
			noPrivsep, hasWait, jsonOut, dryRun, forceAsk, askOnce, hasInspect)
	}
	if reason != "why" || inspect != "9230" {
		t.Errorf("reason=%q inspect=%q", reason, inspect)
	}
	if want := []string{"--", "cmd", "--json"}; !slices.Equal(args, want) {
		t.Errorf("left %q, want %q — the child's argv must be untouched", args, want)
	}
}

// --var is repeatable, takes the attached form too, and stops at the child.
func TestStripExecVars(t *testing.T) {
	args := []string{"--reason", "why", "--var", "DB_URL", "--var=API_KEY", "--json", "--", "cmd", "--var", "X"}
	rest, vars := stripExecVars(args)
	if want := []string{"DB_URL", "API_KEY"}; !slices.Equal(vars, want) {
		t.Errorf("vars = %q, want %q", vars, want)
	}
	if want := []string{"--reason", "why", "--json", "--", "cmd", "--var", "X"}; !slices.Equal(rest, want) {
		t.Errorf("rest = %q, want %q — the child's --var is the child's", rest, want)
	}
	// A --var with nothing after it is not silently a flag with no value.
	rest, vars = stripExecVars([]string{"--var"})
	if len(vars) != 0 || !slices.Equal(rest, []string{"--var"}) {
		t.Errorf("bare --var: vars=%q rest=%q", vars, rest)
	}
}
