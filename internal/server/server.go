package server

import (
 "fmt"
 "log"
 "net/http"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
 mux *http.ServeMux
}

// New creates a new Straja server with all routes registered.
func New() *Server {
 mux := http.NewServeMux()

 // Simple health endpoint for now
 mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "ok")
 })

 return &Server{
  mux: mux,
 }
}

// Start runs the HTTP server on the given address.
func (s *Server) Start(addr string) error {
 log.Printf("Straja Gateway running on %s", addr)
 return http.ListenAndServe(addr, s.mux)
}
