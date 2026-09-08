package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var buildIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`)

type buildPointer struct {
	SchemaVersion int    `json:"schema_version"`
	Build         string `json:"build"`
}

type installationMetadata struct {
	SchemaVersion int    `json:"schema_version"`
	Product       string `json:"product"`
	DataDirectory string `json:"data_directory"`
}

// A missing pointer preserves the legacy development launcher. An invalid
// pointer never falls back to stale binaries or a different account profile.
func resolveManagedRoot(root string) (buildRoot, dataRoot string, err error) {
	data, err := os.ReadFile(filepath.Join(root, "current.json"))
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(filepath.Join(root, "installation.json")); markerErr == nil {
			return "", "", errors.New("managed installation has no active build; run routerctl repair")
		}
		return root, "", nil
	}
	if err != nil {
		return "", "", err
	}
	var pointer buildPointer
	if err := json.Unmarshal(data, &pointer); err != nil {
		return "", "", err
	}
	if pointer.SchemaVersion != 1 || !buildIDPattern.MatchString(pointer.Build) || strings.Contains(pointer.Build, "..") || strings.HasSuffix(pointer.Build, ".") {
		return "", "", errors.New("invalid managed build pointer")
	}
	marker, err := os.ReadFile(filepath.Join(root, "installation.json"))
	if err != nil {
		return "", "", err
	}
	var install installationMetadata
	if err := json.Unmarshal(marker, &install); err != nil {
		return "", "", err
	}
	if install.SchemaVersion != 1 || install.Product != validationOwnerName || (install.DataDirectory != "Data" && install.DataDirectory != validationProfileName) {
		return "", "", errors.New("invalid managed installation metadata")
	}
	buildRoot = filepath.Join(root, "builds", pointer.Build)
	dataRoot = filepath.Join(root, install.DataDirectory)
	for _, path := range []string{filepath.Join(root, "builds"), buildRoot, dataRoot} {
		if err := rejectRedirectedPath(path); err != nil {
			return "", "", err
		}
	}
	return buildRoot, dataRoot, nil
}

func rejectRedirectedPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Resolve the parent too, allowing Windows' benign 8.3 spelling of TEMP.
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(resolved), filepath.Join(parent, filepath.Base(path))) {
		return fmt.Errorf("managed path must not redirect to another location: %s", path)
	}
	return nil
}
