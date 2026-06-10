// Package bynfile parses the `.byn` workspace manifest (strict TOML;
// unknown keys fail). Shared by CLI discovery (scope resolution) and the
// daemon (server-side [exec] env allowlist enforcement in exec.fetch) so
// both sides read the file identically.
package bynfile

import (
	"bytes"

	"github.com/pelletier/go-toml/v2"
)

// File is the parsed `.byn`.
type File struct {
	Scope struct {
		Vault   string `toml:"vault,omitempty"`
		Project string `toml:"project,omitempty"`
		Env     string `toml:"env,omitempty"`
	} `toml:"scope"`
	Exec struct {
		// Env is the `byn exec` allowlist: which scope vars to inject.
		// "*" = all (loud); a list = only those names; empty/absent = none.
		Env EnvList `toml:"env,omitempty"`
	} `toml:"exec"`
}

// EnvList accepts a bare string (env = "*") or a list of strings
// (env = ["*"] / ["VAR1","VAR2"]).
type EnvList []string

// UnmarshalText lets a bare string decode into a one-element list. A TOML
// array decodes natively into []string without this method.
func (e *EnvList) UnmarshalText(text []byte) error {
	*e = EnvList{string(text)}
	return nil
}

// Parse decodes body as a strict-TOML .byn.
func Parse(body []byte) (File, error) {
	var f File
	dec := toml.NewDecoder(bytes.NewReader(body)).DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, err
	}
	return f, nil
}

// AllowsAll reports whether the [exec] env allowlist contains "*".
func (f File) AllowsAll() bool {
	for _, n := range f.Exec.Env {
		if n == "*" {
			return true
		}
	}
	return false
}
