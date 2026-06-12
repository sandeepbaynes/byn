package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestResolveSudoUID(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantUID int
		wantOK  bool
	}{
		{"normal sudo", map[string]string{"SUDO_UID": "501"}, 501, true},
		{"unset (real root)", map[string]string{}, 0, false},
		{"empty", map[string]string{"SUDO_UID": ""}, 0, false},
		{"zero (real root via sudo -u root?)", map[string]string{"SUDO_UID": "0"}, 0, false},
		{"garbage", map[string]string{"SUDO_UID": "notanint"}, 0, false},
		{"negative", map[string]string{"SUDO_UID": "-5"}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			uid, ok := resolveSudoUID(getenv)
			if uid != tc.wantUID || ok != tc.wantOK {
				t.Errorf("resolveSudoUID = (%d,%v), want (%d,%v)", uid, ok, tc.wantUID, tc.wantOK)
			}
		})
	}
}

func TestResolveLegacyDir(t *testing.T) {
	home := t.TempDir()
	bynDir := filepath.Join(home, ".byn")

	lookupAlice := func(name string) (*user.User, error) {
		if name == "alice" {
			return &user.User{Username: "alice", HomeDir: home}, nil
		}
		return nil, errors.New("no such user")
	}

	t.Run("no SUDO_USER skips (fresh)", func(t *testing.T) {
		getenv := func(string) string { return "" }
		dir, exists, err := resolveLegacyDir(getenv, lookupAlice, os.Stat)
		if err != nil || exists || dir != "" {
			t.Fatalf("got (%q,%v,%v), want skip", dir, exists, err)
		}
	})

	t.Run("SUDO_USER unknown errors", func(t *testing.T) {
		getenv := func(k string) string { return map[string]string{"SUDO_USER": "ghost"}[k] }
		_, _, err := resolveLegacyDir(getenv, lookupAlice, os.Stat)
		if err == nil {
			t.Fatal("expected an error for an unknown SUDO_USER")
		}
	})

	t.Run("legacy absent", func(t *testing.T) {
		getenv := func(k string) string { return map[string]string{"SUDO_USER": "alice"}[k] }
		dir, exists, err := resolveLegacyDir(getenv, lookupAlice, os.Stat)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if exists {
			t.Error("exists = true but ~/.byn was never created")
		}
		if dir != bynDir {
			t.Errorf("dir = %q, want %q", dir, bynDir)
		}
	})

	t.Run("legacy present", func(t *testing.T) {
		if err := os.MkdirAll(bynDir, 0o700); err != nil {
			t.Fatal(err)
		}
		getenv := func(k string) string { return map[string]string{"SUDO_USER": "alice"}[k] }
		dir, exists, err := resolveLegacyDir(getenv, lookupAlice, os.Stat)
		if err != nil || !exists || dir != bynDir {
			t.Fatalf("got (%q,%v,%v), want (%q,true,nil)", dir, exists, err, bynDir)
		}
	})

	t.Run("stat error surfaces", func(t *testing.T) {
		getenv := func(k string) string { return map[string]string{"SUDO_USER": "alice"}[k] }
		boom := func(string) (os.FileInfo, error) { return nil, errors.New("permission denied") }
		_, _, err := resolveLegacyDir(getenv, lookupAlice, boom)
		if err == nil {
			t.Fatal("expected the stat error to surface (not silently treated as absent)")
		}
	})

	t.Run("empty home errors", func(t *testing.T) {
		lookupNoHome := func(string) (*user.User, error) { return &user.User{Username: "bob"}, nil }
		getenv := func(k string) string { return map[string]string{"SUDO_USER": "bob"}[k] }
		_, _, err := resolveLegacyDir(getenv, lookupNoHome, os.Stat)
		if err == nil {
			t.Fatal("expected an error when the invoking user has no home dir")
		}
	})
}
