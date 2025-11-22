package console

import (
	"embed"
	"io/fs"
	"net/http"
)

// Embed the entire static folder (HTML + JS + CSS + IMG)
//
//go:embed static/*
var embeddedStatic embed.FS

func Handler() http.Handler {
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
		serveIndex(w, staticFS)
	})
	mux.HandleFunc("/console/", func(w http.ResponseWriter, r *http.Request) {
		serveIndex(w, staticFS)
	})

	return mux
}

// serveIndex loads static/index.html
func serveIndex(w http.ResponseWriter, staticFS fs.FS) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	data, err := fs.ReadFile(staticFS, "console.html")
	if err != nil {
		http.Error(w, "Console UI missing (console.html not found)", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(data)
}
