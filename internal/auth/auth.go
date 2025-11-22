package auth

import (
	"fmt"

	"github.com/straja-ai/straja/internal/config"
)

// Project is the runtime representation of a project with its provider binding.
type Project struct {
	ID       string
	Provider string
}

// Auth holds mappings from API keys to projects.
type Auth struct {
	apiKeyToProject map[string]Project
}

// NewAuth is a convenience constructor that panics on invalid config.
// Useful for tests or places where config is already validated.
func NewAuth(cfg *config.Config) *Auth {
	a, err := NewFromConfig(cfg)
	if err != nil {
		// For now, fail fast – in tests or well-formed configs this should not happen.
		panic(err)
	}
	return a
}

// NewFromConfig builds an Auth instance from the loaded config, with validation.
func NewFromConfig(cfg *config.Config) (*Auth, error) {
	m := make(map[string]Project)

	for _, p := range cfg.Projects {
		if p.ID == "" {
			return nil, fmt.Errorf("project with empty id in config")
		}
		proj := Project{
			ID:       p.ID,
			Provider: p.Provider,
		}
		for _, key := range p.APIKeys {
			if key == "" {
				continue
			}
			if _, exists := m[key]; exists {
				return nil, fmt.Errorf("api key %q is assigned to multiple projects", key)
			}
			m[key] = proj
		}
	}

	return &Auth{
		apiKeyToProject: m,
	}, nil
}

// Lookup returns the project for a given API key, if any.
func (a *Auth) Lookup(apiKey string) (Project, bool) {
	if a == nil {
		return Project{}, false
	}
	p, ok := a.apiKeyToProject[apiKey]
	return p, ok
}
