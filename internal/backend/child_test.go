package backend

import "testing"

func TestWithEnvironmentReplacesExactKey(t *testing.T) {
	environment := withEnvironment([]string{"CODEX_HOME=old", "PATH=unchanged"}, "CODEX_HOME", "new")
	if len(environment) != 2 {
		t.Fatalf("withEnvironment() returned %d entries, want 2: %#v", len(environment), environment)
	}
	if environment[0] != "PATH=unchanged" || environment[1] != "CODEX_HOME=new" {
		t.Fatalf("withEnvironment() = %#v, want PATH and replacement CODEX_HOME", environment)
	}
}
