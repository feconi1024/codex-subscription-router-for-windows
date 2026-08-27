//go:build windows

package backend

import "testing"

func TestWithEnvironmentReplacesCaseInsensitiveWindowsKey(t *testing.T) {
	environment := withEnvironment([]string{"CODEX_HOME=old", "Codex_Home=stale", "PATH=unchanged"}, "CODEX_HOME", "new")
	if len(environment) != 2 {
		t.Fatalf("withEnvironment() returned %d entries, want 2: %#v", len(environment), environment)
	}
	if environment[0] != "PATH=unchanged" || environment[1] != "CODEX_HOME=new" {
		t.Fatalf("withEnvironment() = %#v, want PATH and one CODEX_HOME replacement", environment)
	}
}
