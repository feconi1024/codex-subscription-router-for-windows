package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInteractiveAppServerDetection(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{args: []string{"-c", "features.code_mode_host=true", "app-server", "--analytics-default-enabled"}, want: true},
		{args: []string{"app-server", "daemon", "version"}, want: false},
		{args: []string{"app-server", "generate-ts", "--out", "/tmp/schema"}, want: false},
		{args: []string{"exec", "hello"}, want: false},
	}
	for _, test := range tests {
		if got := isInteractiveAppServer(test.args); got != test.want {
			t.Fatalf("isInteractiveAppServer(%q)=%v, want %v", test.args, got, test.want)
		}
	}
}

func TestValidateControlToken(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got, err := validateControlToken("\n" + valid + "\t"); err != nil || got != valid {
		t.Fatalf("validateControlToken(valid) = %q, %v", got, err)
	}
	for _, invalid := range []string{"short", valid + "00", valid[:63] + "z"} {
		if _, err := validateControlToken(invalid); err == nil {
			t.Fatalf("validateControlToken(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestRealExecutablePath(t *testing.T) {
	wrapper := filepath.Join(t.TempDir(), "codex-mux")
	want := filepath.Join(filepath.Dir(wrapper), defaultRealExecutableName())
	if got := realExecutablePath(wrapper); got != want {
		t.Fatalf("realExecutablePath(%q) = %q, want %q", wrapper, got, want)
	}
}

func TestResolveRealExecutableUsesExplicitOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "codex.override")
	if err := os.WriteFile(override, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_MUX_REAL_CODEX", override)

	got, err := resolveRealExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if got != override {
		t.Fatalf("resolveRealExecutable() = %q, want exact override %q", got, override)
	}
}

func TestResolveRealExecutableRejectsMissingOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "missing-codex")
	t.Setenv("CODEX_MUX_REAL_CODEX", override)

	if _, err := resolveRealExecutable(); err == nil {
		t.Fatalf("resolveRealExecutable() unexpectedly accepted missing override %q", override)
	}
}
