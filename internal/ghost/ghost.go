// Copyright (c) 2026 apetl.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package ghost handles reading and writing .ghost YAML files.
package ghost

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/goccy/go-yaml"
)

// FileData stores metadata about tracked files.
type FileData struct {
	Blake2b  string    `yaml:"Blake2b"`
	Size     int64     `yaml:"size,omitempty"`
	Modified time.Time `yaml:"modified,omitempty"`
	Mode     string    `yaml:"mode,omitempty"`
}

// ReadGhost reads a .ghost YAML file and returns the file metadata map.
// If the file does not exist or is empty, an empty map is returned.
func ReadGhost(ghostPath string) (map[string]FileData, error) {
	data := make(map[string]FileData)
	b, err := os.ReadFile(ghostPath)
	if os.IsNotExist(err) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read ghost file '%s': %w", ghostPath, err)
	}
	if len(b) == 0 {
		return data, nil
	}
	if err := yaml.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("failed to parse YAML from '%s': %w", ghostPath, err)
	}
	return data, nil
}

// WriteGhost marshals the file metadata map and writes it atomically to ghostPath.
func WriteGhost(data map[string]FileData, ghostPath string) error {
	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}
	dir := filepath.Dir(ghostPath)
	tmp, err := os.CreateTemp(dir, ".ghost-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, ghostPath); err != nil {
		return fmt.Errorf("failed to finalize ghost file: %w", err)
	}
	ok = true
	return nil
}

// NeedsRehash returns true if the file's size or modification time differs
// from the stored metadata.
func NeedsRehash(st os.FileInfo, stored FileData) bool {
	return st.Size() != stored.Size || !st.ModTime().Equal(stored.Modified)
}
