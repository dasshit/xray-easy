// Package ui serves the embedded web application and its security boundary.
package ui

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
)

// defaultUIDir is an internal package constant.
const defaultUIDir = "/usr/share/xray-easy/ui"

// Handler serves the static UI shipped separately from the Go binary.
func Handler() http.Handler {
	uiDir := os.Getenv("XRAY_EASY_UI_DIR")
	if uiDir == "" {
		uiDir = defaultUIDir
	}
	return HandlerFromFS(os.DirFS(uiDir))
}

// HandlerFromFS handles the supplied event.
func HandlerFromFS(root fs.FS) http.Handler {
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || !strings.Contains(r.URL.Path, ".") {
			index, err := fs.ReadFile(root, "index.html")
			if err != nil {
				http.Error(w, "UI is unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(index)
			return
		}
		files.ServeHTTP(w, r)
	})
}
