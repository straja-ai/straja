package config

import (
 "os"

 "gopkg.in/yaml.v3"
)

// Config holds Straja configuration.
// We'll expand this as we add providers, policies, etc.
type Config struct {
 Server ServerConfig `yaml:"server"`
}

type ServerConfig struct {
 Addr string `yaml:"addr"` // HTTP listen address, e.g. ":8080"
}

// Load reads configuration from a YAML file.
// If the file doesn't exist, it returns a default config and no error.
func Load(path string) (*Config, error) {
 data, err := os.ReadFile(path)
 if err != nil {
  // If file doesn't exist, return default config
  if os.IsNotExist(err) {
   return &Config{
    Server: ServerConfig{
     Addr: ":8080",
    },
   }, nil
  }
  return nil, err
 }

 var cfg Config
 if err := yaml.Unmarshal(data, &cfg); err != nil {
  return nil, err
 }

 // Fill defaults if needed
 if cfg.Server.Addr == "" {
  cfg.Server.Addr = ":8080"
 }

 return &cfg, nil
}
