package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedBuildSwitchKeepsDataOutsideBuild(t *testing.T) {
	root := t.TempDir()
	for _, version := range []string{"old", "new"} {
		if err := os.MkdirAll(filepath.Join(root, "builds", version), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "installation.json"), []byte(`{"schema_version":1,"product":"Codex Subscription Router","data_directory":"Data"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"old", "new"} {
		if err := os.WriteFile(filepath.Join(root, "current.json"), []byte(`{"schema_version":1,"build":"`+version+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		build, data, err := resolveManagedRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		if build != filepath.Join(root, "builds", version) || data != filepath.Join(root, "Data") {
			t.Fatalf("unexpected managed paths: %s %s", build, data)
		}
	}
}

func TestManagedMalformedPointerNeverUsesLegacy(t *testing.T) {
	for _, value := range []string{`{`, `{"schema_version":2,"build":"old"}`, `{"schema_version":1,"build":"../Data"}`, `{"schema_version":1,"build":"new."}`, `{"schema_version":1,"build":"C:\\outside"}`} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "current.json"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := resolveManagedRoot(root); err == nil {
			t.Fatalf("accepted malformed pointer %s", value)
		}
	}
}

func TestManagedMissingPointerDoesNotUseUninstalledBuild(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "installation.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveManagedRoot(root); err == nil {
		t.Fatal("managed root without pointer was accepted")
	}
}
