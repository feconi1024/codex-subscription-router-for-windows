package control

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Export only categorical status, never paths or raw diagnostic messages.
func readInstallationJSON(path string, value any) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 1024*1024)).Decode(value) == nil
}

var installationBuildID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`)

func (s *Server) installationStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	result := map[string]string{"update": "UNKNOWN", "computerUse": "UNKNOWN"}
	root := os.Getenv("CODEX_MUX_INSTALLATION_ROOT")
	if filepath.IsAbs(root) {
		var marker struct {
			Product string `json:"product"`
			Schema  int    `json:"schema_version"`
		}
		if readInstallationJSON(filepath.Join(root, "installation.json"), &marker) && marker.Schema == 1 && marker.Product == "Codex Subscription Router" {
			var last struct {
				Status string `json:"status"`
			}
			if readInstallationJSON(filepath.Join(root, "last-maintenance.json"), &last) {
				switch last.Status {
				case "SOURCE_REVIEW_REQUIRED", "UPDATED", "UNCHANGED", "ROLLED_BACK":
					result["update"] = last.Status
				}
			}
			var pointer struct {
				Build  string `json:"build"`
				Schema int    `json:"schema_version"`
			}
			if readInstallationJSON(filepath.Join(root, "current.json"), &pointer) && pointer.Schema == 1 && installationBuildID.MatchString(pointer.Build) && !strings.Contains(pointer.Build, "..") && !strings.HasSuffix(pointer.Build, ".") {
				var metadata struct {
					Native struct {
						Status string `json:"status"`
					} `json:"computer_use"`
				}
				if readInstallationJSON(filepath.Join(root, "builds", pointer.Build, "metadata.json"), &metadata) {
					switch metadata.Native.Status {
					case "UNAVAILABLE", "NOT_REQUESTED", "VERIFIED":
						result["computerUse"] = metadata.Native.Status
					}
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, result)
}
