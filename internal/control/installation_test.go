package control

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationStatusIsAuthenticatedAndRedacted(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_MUX_INSTALLATION_ROOT", root)
	put := func(name, body string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	put("installation.json", `{"schema_version":1,"product":"Codex Subscription Router"}`)
	put("current.json", `{"schema_version":1,"build":"test-build"}`)
	put("last-maintenance.json", `{"status":"SOURCE_REVIEW_REQUIRED","reason":"private diagnostic"}`)
	put("builds/test-build/metadata.json", `{"computer_use":{"status":"UNAVAILABLE","reason":"private diagnostic"}}`)
	s := New("", "test-token", nil, false)
	request := func(method, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/v1/installation-status", nil)
		r.Header.Set("X-Codex-Mux-Token", token)
		w := httptest.NewRecorder()
		s.installationStatus(w, r)
		return w
	}
	if got := request("GET", ""); got.Code != 401 {
		t.Fatalf("unauthorized: %d", got.Code)
	}
	if got := request("POST", "test-token"); got.Code != 405 {
		t.Fatalf("method: %d", got.Code)
	}
	got := request("GET", "test-token")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "SOURCE_REVIEW_REQUIRED") || !strings.Contains(got.Body.String(), "UNAVAILABLE") || strings.Contains(got.Body.String(), "private") {
		t.Fatal(got.Body.String())
	}
	put("current.json", `{"schema_version":1,"build":"../outside"}`)
	if got := request("GET", "test-token"); !strings.Contains(got.Body.String(), `"computerUse":"UNKNOWN"`) {
		t.Fatal(got.Body.String())
	}
	put("last-maintenance.json", `{"status":"arbitrary private value"}`)
	if got := request("GET", "test-token"); strings.Contains(got.Body.String(), "private") {
		t.Fatal(got.Body.String())
	}
}
