package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsIgnoredWithConfig(t *testing.T) {
	basePath := "/project"

	tests := []struct {
		name  string
		cfg   Config
		path  string
		isDir bool
		want  bool
	}{
		{
			name:  "no patterns",
			cfg:   Config{Ignore: []string{}},
			path:  "/project/file.txt",
			isDir: false,
			want:  false,
		},
		{
			name:  "exact file match",
			cfg:   Config{Ignore: []string{"file.txt"}},
			path:  "/project/file.txt",
			isDir: false,
			want:  true,
		},
		{
			name:  "glob star match",
			cfg:   Config{Ignore: []string{"*.tmp"}},
			path:  "/project/cache.tmp",
			isDir: false,
			want:  true,
		},
		{
			name:  "glob no match",
			cfg:   Config{Ignore: []string{"*.tmp"}},
			path:  "/project/cache.txt",
			isDir: false,
			want:  false,
		},
		{
			name:  "directory pattern matches dir",
			cfg:   Config{Ignore: []string{"node_modules/"}},
			path:  "/project/node_modules",
			isDir: true,
			want:  true,
		},
		{
			name:  "directory pattern does not match file",
			cfg:   Config{Ignore: []string{"node_modules/"}},
			path:  "/project/node_modules",
			isDir: false,
			want:  false,
		},
		{
			name:  "relative path match",
			cfg:   Config{Ignore: []string{"src/*.log"}},
			path:  "/project/src/debug.log",
			isDir: false,
			want:  true,
		},
		{
			name:  "comment ignored",
			cfg:   Config{Ignore: []string{"# this is a comment", "*.tmp"}},
			path:  "/project/file.tmp",
			isDir: false,
			want:  true,
		},
		{
			name:  "empty pattern skipped",
			cfg:   Config{Ignore: []string{"", "*.bak"}},
			path:  "/project/file.bak",
			isDir: false,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIgnoredWithConfig(tt.cfg, tt.path, basePath, tt.isDir)
			if got != tt.want {
				t.Errorf("IsIgnoredWithConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		content string
		wantErr bool
		wantCfg Config
	}{
		{
			name:    "valid config",
			content: "ignore:\n  - \"*.tmp\"\n  - \"node_modules/\"\nbuffer: 262144\nparallel: 4\nquiet: true\nshow_progress: false\nforce: true\n",
			wantErr: false,
			wantCfg: Config{
				Ignore:       []string{"*.tmp", "node_modules/"},
				Buffer:       262144,
				Quiet:        true,
				Parallel:     4,
				Force:        true,
				ShowProgress: false,
			},
		},
		{
			name:    "empty config",
			content: "",
			wantErr: false,
			wantCfg: DefaultConfig(),
		},
		{
			name:    "invalid buffer",
			content: "buffer: -1\n",
			wantErr: true,
		},
		{
			name:    "file does not exist",
			content: "",
			wantErr: false,
			wantCfg: DefaultConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.name == "file does not exist" {
				path = filepath.Join(tmpDir, "nonexistent.yaml")
			} else {
				path = filepath.Join(tmpDir, tt.name+".yaml")
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			cfg, err := LoadConfigFromFile(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadConfigFromFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if cfg.Buffer != tt.wantCfg.Buffer {
				t.Errorf("Buffer = %d, want %d", cfg.Buffer, tt.wantCfg.Buffer)
			}
			if cfg.Parallel != tt.wantCfg.Parallel {
				t.Errorf("Parallel = %d, want %d", cfg.Parallel, tt.wantCfg.Parallel)
			}
			if cfg.Quiet != tt.wantCfg.Quiet {
				t.Errorf("Quiet = %v, want %v", cfg.Quiet, tt.wantCfg.Quiet)
			}
			if cfg.Force != tt.wantCfg.Force {
				t.Errorf("Force = %v, want %v", cfg.Force, tt.wantCfg.Force)
			}
			if cfg.ShowProgress != tt.wantCfg.ShowProgress {
				t.Errorf("ShowProgress = %v, want %v", cfg.ShowProgress, tt.wantCfg.ShowProgress)
			}
			if len(cfg.Ignore) != len(tt.wantCfg.Ignore) {
				t.Errorf("Ignore len = %d, want %d", len(cfg.Ignore), len(tt.wantCfg.Ignore))
			}
		})
	}
}
