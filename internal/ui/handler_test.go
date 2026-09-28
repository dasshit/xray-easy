package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"testing/fstest"
)

func TestHandlerFromFSFallbackAndStaticAssetRoutes(t *testing.T) {
	root := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<!doctype html><title>UI</title>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('ui')")},
	}
	handler := HandlerFromFS(root)
	for _, path := range []string{"/", "/index.html", "/settings"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(response.Body.String(), "<title>UI</title>") {
			t.Errorf("fallback %s = %d %q %s", path, response.Code, response.Header().Get("Content-Type"), response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "console.log") {
		t.Fatalf("asset response = %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/anything", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("API path should not be served by the UI handler: %d", response.Code)
	}
}

func TestHandlerFromFSReportsMissingIndex(t *testing.T) {
	response := httptest.NewRecorder()
	HandlerFromFS(fstest.MapFS{}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "UI is unavailable") {
		t.Fatalf("missing index response = %d %s", response.Code, response.Body.String())
	}
}

func TestHandlerReadsConfiguredDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("configured UI"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_EASY_UI_DIR", directory)
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || response.Body.String() != "configured UI" {
		t.Fatalf("configured UI response = %d %q", response.Code, response.Body.String())
	}
}
