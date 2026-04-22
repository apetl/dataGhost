// Package config handles .ghostconf parsing, defaults, and ignore-pattern matching.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/goccy/go-yaml"
)

// Config represents configuration settings from a .ghostconf file.
type Config struct {
	Ignore       []string `yaml:"ignore"`
	Buffer       int      `yaml:"buffer"`
	Quiet        bool     `yaml:"quiet"`
	Parallel     int      `yaml:"parallel"`
	Force        bool     `yaml:"force"`
	ShowProgress bool     `yaml:"show_progress"`
}

// DefaultConfig returns the default configuration values.
func DefaultConfig() Config {
	return Config{
		Ignore:       []string{},
		Buffer:       0,
		Quiet:        false,
		Parallel:     runtime.NumCPU(),
		Force:        false,
		ShowProgress: true,
	}
}

// LoadConfigFromFile reads a YAML config file and returns the parsed Config.
// If the file does not exist, DefaultConfig is returned without error.
func LoadConfigFromFile(configPath string) (Config, error) {
	cfg := DefaultConfig()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return cfg, nil
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, fmt.Errorf("failed to read config file '%s': %w", configPath, err)
	}
	if len(b) == 0 {
		return cfg, nil
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config YAML from '%s': %w", configPath, err)
	}
	if cfg.Buffer < 0 {
		return cfg, fmt.Errorf("invalid buffer value %d in '%s': must be >= 0", cfg.Buffer, configPath)
	}
	return cfg, nil
}

// IsIgnoredWithConfig checks ignore patterns using a pre-resolved config,
// avoiding a per-file cache lookup during directory walks.
func IsIgnoredWithConfig(cfg Config, path, basePath string, isDir bool) bool {
	if len(cfg.Ignore) == 0 {
		return false
	}
	relPath, err := filepath.Rel(basePath, path)
	if err != nil {
		relPath = filepath.Base(path)
	}
	relPath = filepath.ToSlash(relPath)
	baseName := filepath.Base(path)

	for _, pattern := range cfg.Ignore {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		pattern = filepath.ToSlash(pattern)
		isDirPattern := strings.HasSuffix(pattern, "/")
		if isDirPattern {
			pattern = strings.TrimSuffix(pattern, "/")
		}
		if isDirPattern && !isDir {
			continue
		}
		matchName, _ := filepath.Match(pattern, baseName)
		matchPath, _ := filepath.Match(pattern, relPath)
		if matchName || matchPath {
			return true
		}
		if isDirPattern && strings.HasPrefix(relPath, pattern+"/") {
			return true
		}
	}
	return false
}
