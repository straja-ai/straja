package auth

import (
	"fmt"

	"github.com/straja-ai/straja-gateway/internal/config"
)

// Project is the runtime representation of a project with its provider binding.
type Project struct {
	ID          string
	Provider    string
	Passthrough bool // accept any Bearer token and forward to upstream
}

// Auth holds mappings from API keys to projects.
type Auth struct {
	apiKeyToProject    map[string]Project
	passthroughProject *Project // if set, matches any Bearer token not matched by apiKeyToProject
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
	var passthrough *Project

	for _, p := range cfg.Projects {
		if p.ID == "" {
			return nil, fmt.Errorf("project with empty id in config")
		}
		isPassthrough := p.AuthMode == "passthrough"
		proj := Project{
			ID:          p.ID,
			Provider:    p.Provider,
			Passthrough: isPassthrough,
		}
		if isPassthrough {
			if passthrough != nil {
				return nil, fmt.Errorf("multiple passthrough projects not allowed (project %q and %q)", passthrough.ID, p.ID)
			}
			pp := proj
			passthrough = &pp
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
		apiKeyToProject:    m,
		passthroughProject: passthrough,
	}, nil
}

// Lookup returns the project for a given API key, if any.
// For passthrough projects, any Bearer token is accepted if no exact key match is found.
func (a *Auth) Lookup(apiKey string) (Project, bool) {
	if a == nil {
		return Project{}, false
	}
	if p, ok := a.apiKeyToProject[apiKey]; ok {
		return p, true
	}
	// Fall back to passthrough project: accept any non-empty token.
	if a.passthroughProject != nil && apiKey != "" {
		return *a.passthroughProject, true
	}
	return Project{}, false
}
