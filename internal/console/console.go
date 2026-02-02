package console

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Embed the entire static folder (HTML + JS + CSS + IMG)
//
//go:embed static/*
var embeddedStatic embed.FS

const (
	// RobotsTagHeader is the header used to block indexing of the console.
	RobotsTagHeader = "X-Robots-Tag"
	// RobotsTagValue disables indexing/caching for console routes.
	RobotsTagValue = "noindex, nofollow, noarchive"
)

func Handler(consoleMode string) http.Handler {
	// Create a sub-FS rooted at /static
	staticFS, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	// Serve static files: /console/static/... → internal/console/static/...
	mux.Handle("/console/static/", http.StripPrefix("/console/static/",
		http.FileServer(http.FS(staticFS)),
	))

	// Serve index.html at both /console and /console/
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		serveIndex(w, staticFS, consoleMode)
	})
	mux.HandleFunc("/console/", func(w http.ResponseWriter, r *http.Request) {
		serveIndex(w, staticFS, consoleMode)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(RobotsTagHeader, RobotsTagValue)
		mux.ServeHTTP(w, r)
	})
}

// serveIndex loads static/index.html
func serveIndex(w http.ResponseWriter, staticFS fs.FS, consoleMode string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	data, err := fs.ReadFile(staticFS, "console.html")
	if err != nil {
		http.Error(w, "Console UI missing (console.html not found)", http.StatusInternalServerError)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(consoleMode))
	if mode != "demo" {
		mode = "local"
	}
	data = bytes.ReplaceAll(data, []byte("__STRAJA_CONSOLE_MODE__"), []byte(mode))
	_, _ = w.Write(data)
}
