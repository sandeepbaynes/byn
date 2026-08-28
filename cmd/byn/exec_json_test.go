package main

import (
	"encoding/json"
	"os"
	"reflect"
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
