package server

import "strings"

// Version returns the gateway version injected at build time.
func Version() string {
	v := strings.TrimSpace(version)
	if v == "" {
		return "dev"
	}
	return v
}
