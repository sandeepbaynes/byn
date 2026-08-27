package main

import (
	"strings"
	"testing"
)

func TestCheckProcVisibility(t *testing.T) {
	prov := healEnv{provisioned: func() bool { return true }}
	cases := []struct {
		name       string
		env        healEnv
		mounts     string
		wantApply  bool
		wantOK     bool
		wantDetail string
	}{
		{
			name:      "not provisioned: nothing runs as another user",
			env:       healEnv{provisioned: func() bool { return false }},
			mounts:    "proc /proc proc rw,hidepid=2 0 0",
			wantApply: false,
		},
		{
			name:      "no /proc line: not applicable",
			env:       prov,
			mounts:    "/dev/sda1 / ext4 rw 0 0",
			wantApply: true, // a /proc with no hidepid option is the healthy case
			wantOK:    true,
		},
		{
			name:      "default proc is fine",
			env:       prov,
			mounts:    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
			wantApply: true,
			wantOK:    true,
		},
		{
			name:      "hidepid=0 is the permissive default",
			env:       prov,
			mounts:    "proc /proc proc rw,hidepid=0 0 0",
			wantApply: true,
			wantOK:    true,
		},
		{
			// The case that silently kills self-authored grants.
			name:       "hidepid=2 hides the ancestry",
			env:        prov,
			mounts:     "proc /proc proc rw,nosuid,hidepid=2 0 0",
			wantApply:  true,
			wantOK:     false,
			wantDetail: "hidepid=2",
		},
		{
			name:       "hidepid=invisible too",
			env:        prov,
			mounts:     "proc /proc proc rw,hidepid=invisible 0 0",
			wantApply:  true,
			wantOK:     false,
			wantDetail: "hidepid=invisible",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, applies := checkProcVisibility(tc.env, tc.mounts)
			if applies != tc.wantApply {
				t.Fatalf("applies = %v, want %v", applies, tc.wantApply)
			}
			if !applies {
				return
			}
			if c.OK != tc.wantOK {
				t.Fatalf("OK = %v, want %v (detail=%q)", c.OK, tc.wantOK, c.Detail)
			}
			if tc.wantDetail != "" && !strings.Contains(c.Detail, tc.wantDetail) {
				t.Errorf("detail %q should mention %q", c.Detail, tc.wantDetail)
			}
			if !c.OK && c.Fix == "" {
				t.Error("a failing check must say what to do about it")
			}
		})
	}
}
