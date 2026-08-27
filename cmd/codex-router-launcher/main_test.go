package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveLaunchPathsPrefersChatGPT(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(appDir, "ChatGPT.exe"),
		filepath.Join(appDir, "Codex.exe"),
		filepath.Join(runtimeDir, "codex-mux.exe"),
		filepath.Join(runtimeDir, "codex.real.exe"),
	} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := resolveLaunchPaths(filepath.Join(root, "Codex Subscription Router.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if paths.chatGPT != filepath.Join(appDir, "ChatGPT.exe") {
		t.Fatalf("chatGPT=%q", paths.chatGPT)
	}
	if paths.userData != filepath.Join(root, "User Data") {
		t.Fatalf("userData=%q", paths.userData)
	}
}

func TestResolveLaunchPathsSupportsLegacyCodex(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app", "resources"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "app", "Codex.exe"),
		filepath.Join(root, "runtime", "codex-mux.exe"),
		filepath.Join(root, "runtime", "codex.real.exe"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := resolveLaunchPaths(filepath.Join(root, "router.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(paths.chatGPT, filepath.Join("app", "Codex.exe")) {
		t.Fatalf("legacy chatGPT=%q", paths.chatGPT)
	}
}

func TestBuildEnvironmentReplacesKeysCaseInsensitively(t *testing.T) {
	environment := buildEnvironment(
		[]string{"Path=one", "codex_cli_path=old", "KEEP=value"},
		map[string]string{"CODEX_CLI_PATH": "new", "CODEX_MUX_REAL_CODEX": "real"},
	)
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "codex_cli_path=old") || !strings.Contains(joined, "CODEX_CLI_PATH=new") {
		t.Fatalf("environment=%q", environment)
	}
	if !strings.Contains(joined, "KEEP=value") {
		t.Fatalf("environment lost unrelated key: %q", environment)
	}
}

func TestIsolatedArgumentsAlwaysUseRouterProfile(t *testing.T) {
	arguments := isolatedArguments([]string{"--foo", "bar", "--user-data-dir=official", "--user-data-dir", "other"}, `C:\router\User Data`)
	if len(arguments) != 3 || arguments[0] != "--foo" || arguments[1] != "bar" || arguments[2] != `--user-data-dir=C:\router\User Data` {
		t.Fatalf("arguments=%q", arguments)
	}
}
