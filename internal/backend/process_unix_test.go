//go:build !windows

package backend

import "testing"

func TestWithEnvironmentKeepsDifferentlyCasedUnixKey(t *testing.T) {
	environment := withEnvironment([]string{"Codex_Home=old"}, "CODEX_HOME", "new")
	if len(environment) != 2 || environment[0] != "Codex_Home=old" || environment[1] != "CODEX_HOME=new" {
		t.Fatalf("withEnvironment() = %#v, want both case-sensitive Unix keys", environment)
	}
}
