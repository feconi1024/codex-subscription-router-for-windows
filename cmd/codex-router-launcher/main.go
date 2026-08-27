package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	chatGPTExecutableName = "ChatGPT.exe"
	legacyExecutableName  = "Codex.exe"
	muxExecutableName     = "codex-mux.exe"
	realCodexName         = "codex.real.exe"
	userDataDirectoryName = "User Data"
)

type launchPaths struct {
	root     string
	appDir   string
	chatGPT  string
	mux      string
	real     string
	userData string
}

func main() {
	os.Exit(run())
}

func run() int {
	launcher, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Codex Subscription Router: resolve launcher path: %v\n", err)
		return 1
	}
	paths, err := resolveLaunchPaths(launcher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Codex Subscription Router: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(paths.userData, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Codex Subscription Router: create isolated user data: %v\n", err)
		return 1
	}

	environment := buildEnvironment(os.Environ(), map[string]string{
		"CODEX_CLI_PATH":             paths.mux,
		"CODEX_MUX_REAL_CODEX":       paths.real,
		"CODEX_MUX_DESKTOP_USER_DATA": paths.userData,
	})
	arguments := isolatedArguments(os.Args[1:], paths.userData)
	command := exec.Command(paths.chatGPT, arguments...)
	command.Dir = paths.appDir
	command.Env = environment
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Codex Subscription Router: launch ChatGPT.exe: %v\n", err)
		return 1
	}
	return 0
}

func resolveLaunchPaths(launcher string) (launchPaths, error) {
	absoluteLauncher, err := filepath.Abs(launcher)
	if err != nil {
		return launchPaths{}, fmt.Errorf("resolve launcher path: %w", err)
	}
	root := filepath.Dir(absoluteLauncher)
	appDir := filepath.Join(root, "app")
	chatGPT := filepath.Join(appDir, chatGPTExecutableName)
	if !regularFile(chatGPT) {
		chatGPT = filepath.Join(appDir, legacyExecutableName)
	}
	paths := launchPaths{
		root:     root,
		appDir:   appDir,
		chatGPT:  chatGPT,
		mux:      filepath.Join(root, "runtime", muxExecutableName),
		real:     filepath.Join(root, "runtime", realCodexName),
		userData: filepath.Join(root, userDataDirectoryName),
	}
	missing := make([]string, 0, 3)
	if !regularFile(paths.chatGPT) {
		missing = append(missing, filepath.Join("app", filepath.Base(paths.chatGPT)))
	}
	if !regularFile(paths.mux) {
		missing = append(missing, filepath.Join("runtime", muxExecutableName))
	}
	if !regularFile(paths.real) {
		missing = append(missing, filepath.Join("runtime", realCodexName))
	}
	if len(missing) != 0 {
		return launchPaths{}, fmt.Errorf("installation is incomplete; missing %s", strings.Join(missing, ", "))
	}
	return paths, nil
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func buildEnvironment(base []string, values map[string]string) []string {
	result := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			result = append(result, entry)
			continue
		}
		remove := false
		for key := range values {
			if strings.EqualFold(name, key) {
				remove = true
				break
			}
		}
		if !remove {
			result = append(result, entry)
		}
	}
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}

func isolatedArguments(arguments []string, userData string) []string {
	result := make([]string, 0, len(arguments)+1)
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if strings.EqualFold(argument, "--user-data-dir") {
			if index+1 < len(arguments) {
				index++
			}
			continue
		}
		if strings.HasPrefix(strings.ToLower(argument), "--user-data-dir=") {
			continue
		}
		result = append(result, argument)
	}
	return append(result, "--user-data-dir="+userData)
}
