package vault

import (
	"context"
	"errors"
	"testing"
)

func TestSource_String(t *testing.T) {
	if SourceScope.String() != "scope" {
		t.Fatalf("got %q", SourceScope.String())
	}
	if SourceDefault.String() != "default" {
		t.Fatalf("got %q", SourceDefault.String())
	}
	if Source(99).String() != "unknown" {
		t.Fatalf("got %q", Source(99).String())
	}
}

func TestVaultID_NonEmpty(t *testing.T) {
	st, _ := newOpenedVault(t)
	if st.VaultID() == "" {
		t.Fatal("VaultID empty")
	}
}

func TestScope_Validate_BadProject(t *testing.T) {
	if err := (Scope{Project: "", Env: DefaultEnvName}).Validate(); err == nil {
		t.Fatal("expected err for empty project")
	}
}

func TestScope_Validate_BadEnv(t *testing.T) {
	if err := (Scope{Project: DefaultProjectName, Env: ""}).Validate(); err == nil {
		t.Fatal("expected err for empty env")
	}
}

func TestScope_Validate_OK(t *testing.T) {
	if err := (Scope{Project: DefaultProjectName, Env: DefaultEnvName}).Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestRenameProject_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.RenameProject(context.Background(), "ghost", "newghost")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenameProject_SameNameNoop(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.RenameProject(context.Background(), DefaultProjectName, DefaultProjectName); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestRenameProject_DuplicateName(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateProject(ctx, "p1"); err != nil {
		t.Fatalf("p1: %v", err)
	}
	if err := st.CreateProject(ctx, "p2"); err != nil {
		t.Fatalf("p2: %v", err)
	}
	err := st.RenameProject(ctx, "p1", "p2")
	if !errors.Is(err, ErrProjectExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenameProject_BadNames(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.RenameProject(context.Background(), "", "x"); err == nil {
		t.Fatal("empty old")
	}
	if err := st.RenameProject(context.Background(), DefaultProjectName, ""); err == nil {
		t.Fatal("empty new")
	}
}

func TestRenameEnv_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.RenameEnv(context.Background(), DefaultProjectName, "ghost", "newghost")
	if !errors.Is(err, ErrEnvNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenameEnv_SameNameNoop(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.RenameEnv(context.Background(), DefaultProjectName, "stg", "stg"); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestRenameEnv_DuplicateName(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("stg: %v", err)
	}
	if err := st.CreateEnv(ctx, DefaultProjectName, "prd"); err != nil {
		t.Fatalf("prd: %v", err)
	}
	err := st.RenameEnv(ctx, DefaultProjectName, "stg", "prd")
	if !errors.Is(err, ErrEnvExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenameEnv_NewToDefaultRefused(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("stg: %v", err)
	}
	err := st.RenameEnv(ctx, DefaultProjectName, "stg", DefaultEnvName)
	if !errors.Is(err, ErrEnvProtected) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenameEnv_BadNames(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.RenameEnv(context.Background(), "", "a", "b"); err == nil {
		t.Fatal("bad project")
	}
	if err := st.RenameEnv(context.Background(), DefaultProjectName, "", "b"); err == nil {
		t.Fatal("empty old")
	}
	if err := st.RenameEnv(context.Background(), DefaultProjectName, "a", ""); err == nil {
		t.Fatal("empty new")
	}
}

func TestCreateEnv_RefusesBadProject(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.CreateEnv(context.Background(), "", "stg"); err == nil {
		t.Fatal("empty project")
	}
}

func TestCreateEnv_RefusesBadEnv(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.CreateEnv(context.Background(), DefaultProjectName, ""); err == nil {
		t.Fatal("empty env name")
	}
}

func TestDeleteEnv_BadProject(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.DeleteEnv(context.Background(), "", "stg"); err == nil {
		t.Fatal("empty project")
	}
}

func TestDeleteEnv_BadName(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.DeleteEnv(context.Background(), DefaultProjectName, ""); err == nil {
		t.Fatal("empty name")
	}
}

func TestDeleteEnv_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.DeleteEnv(context.Background(), DefaultProjectName, "ghost")
	if !errors.Is(err, ErrEnvNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateEnvName_RejectsBadShape(t *testing.T) {
	if err := ValidateEnvName(""); err == nil {
		t.Fatal("empty")
	}
	if err := ValidateEnvName("a b"); err == nil {
		t.Fatal("space")
	}
}

func TestDeleteProject_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.DeleteProject(context.Background(), "ghost")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteProject_BadName(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.DeleteProject(context.Background(), ""); err == nil {
		t.Fatal("empty")
	}
}
