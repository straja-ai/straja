package main

import (
	"flag"
	"log"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/server"
)

func main() {
	addrFlag := flag.String("addr", "", "HTTP listen address (overrides config)")
	configPath := flag.String("config", "straja.yaml", "Path to Straja config file")
	flag.Parse()

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Build auth mappings
	authz, err := auth.NewFromConfig(cfg)
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	addr := cfg.Server.Addr
	if *addrFlag != "" {
		addr = *addrFlag
	}

	srv := server.New(cfg, authz)

	log.Printf("Starting Straja on %s...", addr)
	if err := srv.Start(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
