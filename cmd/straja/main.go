package main

import (
 "flag"
 "log"

 "github.com/somanole/straja/internal/server"
)

func main() {
 addr := flag.String("addr", ":8080", "HTTP listen address")
 // we’ll add --config later
 flag.Parse()

 srv := server.New()

 log.Printf("Starting Straja on %s...", *addr)
 if err := srv.Start(*addr); err != nil {
  log.Fatalf("server error: %v", err)
 }
}
