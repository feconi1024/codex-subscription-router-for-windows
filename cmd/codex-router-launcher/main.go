package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	chatGPTExecutableName  = "ChatGPT.exe"
	legacyExecutableName   = "Codex.exe"
	muxExecutableName      = "codex-mux.exe"
	realCodexName          = "codex.real.exe"
	userDataDirectoryName  = "User Data"
	codexHomeDirectoryName = "codex-home"
	muxHomeDirectoryName   = "mux-home"
	validationProfileName  = "_validation-profile"
	validationOwnerName    = "Codex Subscription Router"
	muxStateDirectoryName  = ".codex-mux"
	launchMetadataName     = "launch.json"
)

type launchMetadata struct {
	DesktopLaunchExecutable string `json:"desktop_launch_executable"`
}

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
	userData := paths.userData
	muxHome := filepath.Join(paths.root, "runtime", muxStateDirectoryName)
	codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	persistentProfileRoot := strings.TrimSpace(os.Getenv("CODEX_MUX_PERSISTENT_PROFILE_ROOT"))
	if persistentProfileRoot != "" {
		if os.Getenv("CODEX_MUX_UI_TESTS") != "1" {
			fmt.Fprintln(os.Stderr, "Codex Subscription Router: persistent validation profile is test-only")
			return 1
		}
		profileRoot, profileErr := resolvePersistentProfileRoot(persistentProfileRoot)
		if profileErr != nil {
			fmt.Fprintf(os.Stderr, "Codex Subscription Router: %v\n", profileErr)
			return 1
		}
		userData = filepath.Join(profileRoot, userDataDirectoryName)
		codexHome = filepath.Join(profileRoot, codexHomeDirectoryName)
		muxHome = filepath.Join(profileRoot, muxHomeDirectoryName)
	}
	if err := os.MkdirAll(userData, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Codex Subscription Router: create isolated user data: %v\n", err)
		return 1
	}

	environment := buildEnvironment(os.Environ(), map[string]string{
		"CODEX_CLI_PATH":                paths.mux,
		"CODEX_MUX_REAL_CODEX":          paths.real,
		"CODEX_MUX_HOME":                muxHome,
		"CODEX_MUX_DESKTOP_USER_DATA":   userData,
		"CODEX_ELECTRON_USER_DATA_PATH": userData,
		"CODEX_SPARKLE_ENABLED":         "false",
	})
	if persistentProfileRoot != "" {
		environment = buildEnvironment(environment, map[string]string{
			"CODEX_HOME": codexHome,
		})
	}
	arguments := isolatedArguments(os.Args[1:], userData)
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
		fmt.Fprintf(os.Stderr, "Codex Subscription Router: launch selected Desktop shell: %v\n", err)
		return 1
	}
	return 0
}

func resolvePersistentProfileRoot(requested string) (string, error) {
	root, err := filepath.Abs(filepath.Clean(requested))
	if err != nil {
		return "", fmt.Errorf("resolve persistent validation profile: %w", err)
	}
	if strings.EqualFold(filepath.Base(root), validationProfileName) == false ||
		strings.EqualFold(filepath.Base(filepath.Dir(root)), validationOwnerName) == false {
		return "", fmt.Errorf(
			"persistent validation profile must be %s\\%s",
			validationOwnerName,
			validationProfileName,
		)
	}
	if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
		expected, expectedErr := filepath.Abs(filepath.Join(localAppData, validationOwnerName, validationProfileName))
		if expectedErr != nil || !strings.EqualFold(filepath.Clean(root), filepath.Clean(expected)) {
			return "", errors.New("persistent validation profile is not under LOCALAPPDATA\\Codex Subscription Router")
		}
	}
	for _, component := range strings.FieldsFunc(root, func(r rune) bool { return r == '\\' || r == '/' }) {
		if strings.EqualFold(component, "WindowsApps") {
			return "", errors.New("persistent validation profile must be outside WindowsApps")
		}
	}
	return root, nil
}

func resolveLaunchPaths(launcher string) (launchPaths, error) {
	absoluteLauncher, err := filepath.Abs(launcher)
	if err != nil {
		return launchPaths{}, fmt.Errorf("resolve launcher path: %w", err)
	}
	root := filepath.Dir(absoluteLauncher)
	appDir := filepath.Join(root, "app")
	chatGPT, err := resolveDesktopExecutable(root, appDir)
	if err != nil {
		return launchPaths{}, err
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

func resolveDesktopExecutable(root, appDir string) (string, error) {
	metadataPath := filepath.Join(root, launchMetadataName)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", launchMetadataName, err)
	}
	var metadata launchMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", fmt.Errorf("parse %s: %w", launchMetadataName, err)
	}
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(metadata.DesktopLaunchExecutable), "/", "\\"))
	var name string
	switch normalized {
	case "app\\chatgpt.exe":
		name = chatGPTExecutableName
	case "app\\codex.exe":
		name = legacyExecutableName
	default:
		return "", fmt.Errorf(
			"%s desktop_launch_executable must be app\\%s or app\\%s",
			launchMetadataName,
			chatGPTExecutableName,
			legacyExecutableName,
		)
	}
	selected := filepath.Join(appDir, name)
	if !regularFile(selected) {
		return "", fmt.Errorf("%s selects missing app\\%s", launchMetadataName, name)
	}
	return selected, nil
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
