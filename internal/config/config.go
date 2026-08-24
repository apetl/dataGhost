// Copyright (c) 2026 apetl.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

// StringSlice is a flag.Value that accumulates multiple string flags.
type StringSlice []string

func (s *StringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// CountFlag is a flag.Value that counts repeated occurrences (e.g. -v -v).
type CountFlag int

func (c *CountFlag) String() string {
	return fmt.Sprintf("%d", int(*c))
}

func (c *CountFlag) Set(string) error {
	*c++
	return nil
}

// IsBoolFlag lets -v be used without a value; without it the flag package
// would consume the following argument (e.g. the command name) as the value.
func (c *CountFlag) IsBoolFlag() bool { return true }

// Config represents configuration settings from a .ghostconf file.
type Config struct {
	Ignore        []string `yaml:"ignore"`
	Buffer        int      `yaml:"buffer"`
	Quiet         bool     `yaml:"quiet"`
	Parallel      int      `yaml:"parallel"`
	Force         bool     `yaml:"force"`
	ShowProgress  bool     `yaml:"show_progress"`
	TrackMode     bool     `yaml:"track_mode"`
	FailUntracked bool     `yaml:"fail_untracked"`
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

// GlobalConfigPath returns the path to the user-level config file, honored by
// every run as the lowest-priority config layer. It resolves (in order) the
// DG_CONFIG_HOME env override, then the OS config dir (XDG_CONFIG_HOME or
// ~/./.config on Unix, %AppData% on Windows) under a "dataGhost" subdir.
func GlobalConfigPath() (string, error) {
	if dir := os.Getenv("DG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "config.yaml"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dataGhost", "config.yaml"), nil
}

// LoadConfigInto parses configPath into cfg, overriding only the keys present
// in the file (absent keys keep their existing values). This lets callers layer
// configs: start from defaults, apply global, then apply a local config on top.
// A missing or empty file is a no-op.
func LoadConfigInto(cfg *Config, configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file '%s': %w", configPath, err)
	}
	if len(b) == 0 {
		return nil
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return fmt.Errorf("failed to parse config YAML from '%s': %w", configPath, err)
	}
	if cfg.Buffer < 0 {
		return fmt.Errorf("invalid buffer value %d in '%s': must be >= 0", cfg.Buffer, configPath)
	}
	return ValidateConfig(*cfg, configPath)
}

// LoadConfigFromFile reads a YAML config file and returns the parsed Config.
// If the file does not exist, DefaultConfig is returned without error.
func LoadConfigFromFile(configPath string) (Config, error) {
	cfg := DefaultConfig()
	if err := LoadConfigInto(&cfg, configPath); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ValidateConfig checks a Config for invalid values and returns an error if any are found.
func ValidateConfig(cfg Config, source string) error {
	if cfg.Parallel < 1 {
		return fmt.Errorf("invalid parallel value %d in '%s': must be >= 1", cfg.Parallel, source)
	}
	return nil
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
