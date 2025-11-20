package main

import (
 "fmt"
 "log"
 "net/http"
)

func main() {
 mux := http.NewServeMux()

 // Simple health endpoint
 mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "ok")
 })

 addr := ":8080"
 log.Printf("Straja Gateway running on %s", addr)

 if err := http.ListenAndServe(addr, mux); err != nil {
  log.Fatalf("server error: %v", err)
 }
}
