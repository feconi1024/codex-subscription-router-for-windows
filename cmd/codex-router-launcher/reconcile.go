package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func reconcileAtLaunch(root string) {
	data, err := os.ReadFile(filepath.Join(root, "manager.json"))
	if os.IsNotExist(err) {
		return
	}
	var manager struct {
		SchemaVersion int    `json:"schema_version"`
		Python        string `json:"python"`
		Script        string `json:"script"`
		ScriptHash    string `json:"script_sha256"`
	}
	if err != nil || json.Unmarshal(data, &manager) != nil || manager.SchemaVersion != 1 || !filepath.IsAbs(manager.Python) || !filepath.IsAbs(manager.Script) {
		fmt.Fprintln(os.Stderr, "Router maintenance configuration is unavailable; retaining current build.")
		return
	}
	script, err := os.ReadFile(manager.Script)
	digest := sha256.Sum256(script)
	if err != nil || hex.EncodeToString(digest[:]) != manager.ScriptHash {
		fmt.Fprintln(os.Stderr, "Router source changed; run routerctl update to refresh maintenance configuration.")
		return
	}
	command := exec.Command(manager.Python, manager.Script, "--root", root, "reconcile", "--on-launch")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Router maintenance did not complete; retaining current build.")
	}
}
