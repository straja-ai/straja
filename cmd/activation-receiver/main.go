package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", ":8099", "listen address for activation receiver")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/activation", handleActivation)
	mux.HandleFunc("/", handleActivation)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("activation receiver listening on %s (POST JSON to /activation)...", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("receiver error: %v", err)
	}
}

func handleActivation(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	log.Printf("received activation event: path=%s content-type=%s len=%d\n%s", r.URL.Path, r.Header.Get("Content-Type"), len(body), string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
}
