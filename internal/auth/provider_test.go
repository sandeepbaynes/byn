package auth

import (
	"context"
	"errors"
	"testing"
)

// ---- stub provider ---------------------------------------------------------

type stubProvider struct {
	name   string
	result error // nil = approve, else propagate
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Verify(_ context.Context, _ VerifyRequest) (Grant, error) {
	if s.result != nil {
		return Grant{}, s.result
	}
	return Grant{Provider: s.name}, nil
}

// ---- Registry tests --------------------------------------------------------

func TestRegistry_RegisterAndLookup(t *testing.T) {
	reg := NewRegistry()
	p := &stubProvider{name: "password"}
	reg.Register(p)

	got, ok := reg.Lookup("password")
	if !ok {
		t.Fatal("Lookup: expected ok=true")
	}
	if got.Name() != "password" {
		t.Fatalf("Name = %q, want password", got.Name())
	}
}

func TestRegistry_LookupMissing(t *testing.T) {
	reg := NewRegistry()
	_, ok := reg.Lookup("missing")
	if ok {
		t.Fatal("Lookup missing: expected ok=false")
	}
}

func TestRegistry_ReplaceSameName(t *testing.T) {
	reg := NewRegistry()
	a := &stubProvider{name: "pw", result: ErrDenied}
	b := &stubProvider{name: "pw", result: nil} // will approve
	reg.Register(a)
	reg.Register(b)

	got, ok := reg.Lookup("pw")
	if !ok {
		t.Fatal("Lookup after replace: expected ok=true")
	}
	g, err := got.Verify(context.Background(), VerifyRequest{})
	if err != nil {
		t.Fatalf("Verify after replace: unexpected error %v", err)
	}
	if g.Provider != "pw" {
		t.Fatalf("Grant.Provider = %q, want pw", g.Provider)
	}
}

func TestRegistry_InsertionOrderPreservedOnReplace(t *testing.T) {
	// Registering the same name twice must NOT grow the order slice.
	reg := NewRegistry()
	reg.Register(&stubProvider{name: "a"})
	reg.Register(&stubProvider{name: "b"})
	reg.Register(&stubProvider{name: "a"}) // replace, not append

	if len(reg.order) != 2 {
		t.Fatalf("order len = %d, want 2 (a, b)", len(reg.order))
	}
	if reg.order[0] != "a" || reg.order[1] != "b" {
		t.Fatalf("order = %v, want [a b]", reg.order)
	}
}

// ---- Provider interface / stub tests ----------------------------------------

func TestStubProvider_Approve(t *testing.T) {
	p := &stubProvider{name: "fake-approve"}
	g, err := p.Verify(context.Background(), VerifyRequest{Vault: "v", Action: "get"})
	if err != nil {
		t.Fatalf("Verify: unexpected error %v", err)
	}
	if g.Provider != "fake-approve" {
		t.Fatalf("Grant.Provider = %q, want fake-approve", g.Provider)
	}
}

func TestStubProvider_Deny(t *testing.T) {
	p := &stubProvider{name: "fake-deny", result: ErrDenied}
	_, err := p.Verify(context.Background(), VerifyRequest{Vault: "v", Action: "delete"})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Verify: err = %v, want ErrDenied", err)
	}
}

func TestStubProvider_WrongCredential(t *testing.T) {
	p := &stubProvider{name: "fake-wrong", result: ErrWrongCredential}
	_, err := p.Verify(context.Background(), VerifyRequest{Password: []byte("bad")})
	if !errors.Is(err, ErrWrongCredential) {
		t.Fatalf("err = %v, want ErrWrongCredential", err)
	}
}

// ---- Error sentinel tests ---------------------------------------------------

func TestErrDenied_NotErrWrongCredential(t *testing.T) {
	if errors.Is(ErrDenied, ErrWrongCredential) {
		t.Fatal("ErrDenied must not be ErrWrongCredential")
	}
	if errors.Is(ErrWrongCredential, ErrDenied) {
		t.Fatal("ErrWrongCredential must not be ErrDenied")
	}
}
