package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Files contains the production UI. Docker builds replace this directory with
// the freshly compiled Vite bundle; keeping the bundle in the repository also
// makes a native `go build` serve the same shell.
//
//go:embed dist/*
var Files embed.FS

func Handler() http.Handler {
	root, _ := fs.Sub(Files, "dist")
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
