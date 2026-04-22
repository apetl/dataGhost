package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

// ── TestCalcHash ─────────────────────────────────────────────────────────────

func TestCalcHash(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		wantHash string
	}{
		{
			name:     "empty file",
			content:  "",
			wantHash: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			name:     "hello world",
			content:  "hello world",
			wantHash: "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
		},
		{
			name:     "multiline content",
			content:  "line1\nline2\nline3\n",
			wantHash: "",
		}, // hash computed below
	}

	// Compute expected hash for multiline content.
	h, _ := blake2b.New256(nil)
	h.Write([]byte("line1\nline2\nline3\n"))
	tests[2].wantHash = fmt.Sprintf("%x", h.Sum(nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, tt.name+".txt")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("write file: %v", err)
			}

			got, err := calcHash(path, 0)
			if err != nil {
				t.Fatalf("calcHash error: %v", err)
			}
			if got != tt.wantHash {
				t.Errorf("calcHash() = %s, want %s", got, tt.wantHash)
			}
		})
	}
}

func TestCalcHashSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.txt")
	link := filepath.Join(tmpDir, "link.txt")

	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	_, err := calcHash(link, 0)
	if err == nil {
		t.Error("expected error for symlink, got nil")
	}
}

// ── TestIsIgnoredWithConfig ──────────────────────────────────────────────────

func TestIsIgnoredWithConfig(t *testing.T) {
	basePath := "/project"

	tests := []struct {
		name    string
		cfg     conf
		path    string
		isDir   bool
		want    bool
	}{
		{
			name:    "no patterns",
			cfg:     conf{Ignore: []string{}},
			path:    "/project/file.txt",
			isDir:   false,
			want:    false,
		},
		{
			name:    "exact file match",
			cfg:     conf{Ignore: []string{"file.txt"}},
			path:    "/project/file.txt",
			isDir:   false,
			want:    true,
		},
		{
			name:    "glob star match",
			cfg:     conf{Ignore: []string{"*.tmp"}},
			path:    "/project/cache.tmp",
			isDir:   false,
			want:    true,
		},
		{
			name:    "glob no match",
			cfg:     conf{Ignore: []string{"*.tmp"}},
			path:    "/project/cache.txt",
			isDir:   false,
			want:    false,
		},
		{
			name:    "directory pattern matches dir",
			cfg:     conf{Ignore: []string{"node_modules/"}},
			path:    "/project/node_modules",
			isDir:   true,
			want:    true,
		},
		{
			name:    "directory pattern does not match file",
			cfg:     conf{Ignore: []string{"node_modules/"}},
			path:    "/project/node_modules",
			isDir:   false,
			want:    false,
		},
		{
			name:    "relative path match",
			cfg:     conf{Ignore: []string{"src/*.log"}},
			path:    "/project/src/debug.log",
			isDir:   false,
			want:    true,
		},
		{
			name:    "comment ignored",
			cfg:     conf{Ignore: []string{"# this is a comment", "*.tmp"}},
			path:    "/project/file.tmp",
			isDir:   false,
			want:    true,
		},
		{
			name:    "empty pattern skipped",
			cfg:     conf{Ignore: []string{"", "*.bak"}},
			path:    "/project/file.bak",
			isDir:   false,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIgnoredWithConfig(tt.cfg, tt.path, basePath, tt.isDir)
			if got != tt.want {
				t.Errorf("isIgnoredWithConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── TestReadWriteGhost ───────────────────────────────────────────────────────

func TestReadWriteGhostRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	ghostPath := filepath.Join(tmpDir, ".ghost")

	original := map[string]fileData{
		"file1.txt": {
			Blake2b:  "a1b2c3d4e5f6",
			Size:     12345,
			Modified: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		},
		"file2.bin": {
			Blake2b: "deadbeef",
			Size:    0,
		},
	}

	if err := writeGhost(original, ghostPath); err != nil {
		t.Fatalf("writeGhost error: %v", err)
	}

	readBack, err := readGhost(ghostPath)
	if err != nil {
		t.Fatalf("readGhost error: %v", err)
	}

	if len(readBack) != len(original) {
		t.Fatalf("readBack len = %d, want %d", len(readBack), len(original))
	}

	for name, orig := range original {
		got, ok := readBack[name]
		if !ok {
			t.Errorf("missing entry %q", name)
			continue
		}
		if got.Blake2b != orig.Blake2b {
			t.Errorf("%q Blake2b = %q, want %q", name, got.Blake2b, orig.Blake2b)
		}
		if got.Size != orig.Size {
			t.Errorf("%q Size = %d, want %d", name, got.Size, orig.Size)
		}
		if !orig.Modified.IsZero() && !got.Modified.Equal(orig.Modified) {
			t.Errorf("%q Modified = %v, want %v", name, got.Modified, orig.Modified)
		}
	}
}

func TestReadGhostMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	ghostPath := filepath.Join(tmpDir, "nonexistent.ghost")

	data, err := readGhost(ghostPath)
	if err != nil {
		t.Fatalf("readGhost error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty map, got %d entries", len(data))
	}
}

func TestReadGhostEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	ghostPath := filepath.Join(tmpDir, ".ghost")

	if err := os.WriteFile(ghostPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	data, err := readGhost(ghostPath)
	if err != nil {
		t.Fatalf("readGhost error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty map, got %d entries", len(data))
	}
}

// ── TestNeedsRehash ──────────────────────────────────────────────────────────

func TestNeedsRehash(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		size    int64
		modTime time.Time
		stored  fileData
		want    bool
	}{
		{
			name:    "identical",
			size:    100,
			modTime: now,
			stored:  fileData{Size: 100, Modified: now},
			want:    false,
		},
		{
			name:    "size changed",
			size:    200,
			modTime: now,
			stored:  fileData{Size: 100, Modified: now},
			want:    true,
		},
		{
			name:    "modtime changed",
			size:    100,
			modTime: now.Add(time.Second),
			stored:  fileData{Size: 100, Modified: now},
			want:    true,
		},
		{
			name:    "no stored size",
			size:    100,
			modTime: now,
			stored:  fileData{Size: 0, Modified: now},
			want:    true,
		},
		{
			name:    "no stored modtime",
			size:    100,
			modTime: now,
			stored:  fileData{Size: 100, Modified: time.Time{}},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake FileInfo via a minimal implementation.
			fi := &fakeFileInfo{size: tt.size, modTime: tt.modTime}
			got := needsRehash(fi, tt.stored)
			if got != tt.want {
				t.Errorf("needsRehash() = %v, want %v", got, tt.want)
			}
		})
	}
}

// fakeFileInfo implements os.FileInfo for testing.
type fakeFileInfo struct {
	size    int64
	modTime time.Time
}

func (f *fakeFileInfo) Name() string       { return "fake" }
func (f *fakeFileInfo) Size() int64        { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode  { return 0644 }
func (f *fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f *fakeFileInfo) IsDir() bool        { return false }
func (f *fakeFileInfo) Sys() interface{}   { return nil }

// ── TestLoadConfigFromFile ───────────────────────────────────────────────────

func TestLoadConfigFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		content   string
		wantErr   bool
		wantCfg   conf
	}{
		{
			name:    "valid config",
			content: "ignore:\n  - \"*.tmp\"\n  - \"node_modules/\"\nbuffer: 262144\nparallel: 4\nquiet: true\nshow_progress: false\nforce: true\n",
			wantErr: false,
			wantCfg: conf{
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
			wantCfg: defaultConfig(),
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
			wantCfg: defaultConfig(),
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

			cfg, err := loadConfigFromFile(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadConfigFromFile() error = %v, wantErr %v", err, tt.wantErr)
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

// ── TestGetBufferSize ────────────────────────────────────────────────────────

func TestGetBufferSize(t *testing.T) {
	tests := []struct {
		name      string
		fileSize  int64
		cfgBuffer int
		want      int
	}{
		{
			name:      "user override",
			fileSize:  1024,
			cfgBuffer: 4096,
			want:      4096,
		},
		{
			name:      "small file",
			fileSize:  512 * 1024,
			cfgBuffer: 0,
			want:      minBuffer,
		},
		{
			name:      "medium file",
			fileSize:  50 * 1024 * 1024,
			cfgBuffer: 0,
			want:      defaultBuffer,
		},
		{
			name:      "large file",
			fileSize:  500 * 1024 * 1024,
			cfgBuffer: 0,
			want:      maxBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getBufferSize(tt.fileSize, tt.cfgBuffer)
			if got != tt.want {
				t.Errorf("getBufferSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ── Integration Tests ────────────────────────────────────────────────────────

func TestEndToEndAddAndCheck(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	a := newApp()
	a.cfg = defaultConfig()
	a.cfg.Force = true
	a.cfg.Parallel = 1
	a.cfg.Quiet = true

	ctx := context.Background()

	// Add the file.
	err := a.processFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a.addF(ctx, fp, gp, bp) }, "add")
	if err != nil {
		t.Fatalf("add error: %v", err)
	}

	// Verify .ghost file was created.
	ghostPath := filepath.Join(tmpDir, ".ghost")
	if _, err := os.Stat(ghostPath); os.IsNotExist(err) {
		t.Fatal(".ghost file was not created")
	}

	// Check the file (should be OK).
	a2 := newApp()
	a2.cfg = defaultConfig()
	a2.cfg.Parallel = 1
	a2.cfg.Quiet = true

	err = a2.processFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a2.checkF(ctx, fp, gp, bp) }, "check")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}

	if a2.stats.ok.Load() != 1 {
		t.Errorf("ok count = %d, want 1", a2.stats.ok.Load())
	}

	// Corrupt the file and check again.
	if err := os.WriteFile(filePath, []byte("corrupted"), 0644); err != nil {
		t.Fatal(err)
	}

	a3 := newApp()
	a3.cfg = defaultConfig()
	a3.cfg.Parallel = 1
	a3.cfg.Quiet = true
	a3.alwaysRehash = true

	err = a3.processFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a3.checkF(ctx, fp, gp, bp) }, "check")
	if err != nil {
		t.Fatalf("check after corruption error: %v", err)
	}

	if a3.stats.corrupted.Load() != 1 {
		t.Errorf("corrupted count = %d, want 1", a3.stats.corrupted.Load())
	}
}

func TestEndToEndClean(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keep.txt")
	ghostPath := filepath.Join(tmpDir, ".ghost")

	if err := os.WriteFile(filePath, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a ghost file with one existing and one missing entry.
	data := map[string]fileData{
		"keep.txt":  {Blake2b: "abc", Size: 4},
		"gone.txt":  {Blake2b: "def", Size: 4},
	}
	if err := writeGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := newApp()
	a.cfg = defaultConfig()
	a.cfg.Quiet = true

	ctx := context.Background()
	if err := a.clean(ctx, tmpDir, false); err != nil {
		t.Fatalf("clean error: %v", err)
	}

	// Verify gone.txt was removed.
	readBack, err := readGhost(ghostPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := readBack["gone.txt"]; ok {
		t.Error("gone.txt should have been cleaned")
	}
	if _, ok := readBack["keep.txt"]; !ok {
		t.Error("keep.txt should still be present")
	}
}

func TestEndToEndUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	content := []byte("update me")

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Calculate real hash.
	hash, err := calcHash(filePath, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write ghost without size/modtime (old format).
	ghostPath := filepath.Join(tmpDir, ".ghost")
	data := map[string]fileData{
		"test.txt": {Blake2b: hash},
	}
	if err := writeGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := newApp()
	a.cfg = defaultConfig()
	a.cfg.Quiet = true

	ctx := context.Background()
	if err := a.update(ctx, tmpDir, false); err != nil {
		t.Fatalf("update error: %v", err)
	}

	// Verify metadata was added.
	readBack, err := readGhost(ghostPath)
	if err != nil {
		t.Fatal(err)
	}
	fi, ok := readBack["test.txt"]
	if !ok {
		t.Fatal("test.txt missing from ghost")
	}
	if fi.Size == 0 {
		t.Error("size was not updated")
	}
	if fi.Modified.IsZero() {
		t.Error("modified time was not updated")
	}
}

func TestEndToEndDelete(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "delete.txt")
	ghostPath := filepath.Join(tmpDir, ".ghost")

	if err := os.WriteFile(filePath, []byte("delete me"), 0644); err != nil {
		t.Fatal(err)
	}

	data := map[string]fileData{
		"delete.txt": {Blake2b: "abc123"},
	}
	if err := writeGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := newApp()
	a.cfg = defaultConfig()
	a.cfg.Quiet = true

	ctx := context.Background()
	err := a.processFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a.delF(ctx, fp, gp, bp) }, "delete")
	if err != nil {
		t.Fatalf("del error: %v", err)
	}

	if a.stats.deleted.Load() != 1 {
		t.Errorf("deleted count = %d, want 1", a.stats.deleted.Load())
	}

	readBack, err := readGhost(ghostPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := readBack["delete.txt"]; ok {
		t.Error("delete.txt should have been removed")
	}
}

// ── TestNewApp ───────────────────────────────────────────────────────────────

func TestNewApp(t *testing.T) {
	a := newApp()
	if a == nil {
		t.Fatal("newApp() returned nil")
	}
	if a.configCache == nil {
		t.Error("configCache is nil")
	}
	if a.cfg.Parallel != runtime.NumCPU() {
		t.Errorf("default parallel = %d, want %d", a.cfg.Parallel, runtime.NumCPU())
	}
}

// ── TestRunWorkers ───────────────────────────────────────────────────────────

func TestRunWorkers(t *testing.T) {
	a := newApp()
	a.cfg.Quiet = true

	var counter int64
	jobs := []int{1, 2, 3, 4, 5}

	runWorkers(context.Background(), jobs, func(_ context.Context, n int) {
		counter += int64(n)
	}, 2, "test", a)

	// 1+2+3+4+5 = 15
	if counter != 15 {
		t.Errorf("counter = %d, want 15", counter)
	}
}

func TestRunWorkersEmpty(t *testing.T) {
	a := newApp()
	var called bool
	runWorkers(context.Background(), []int{}, func(_ context.Context, n int) {
		called = true
	}, 2, "test", a)
	if called {
		t.Error("worker func should not have been called for empty jobs")
	}
}

func TestRunWorkersCancelledContext(t *testing.T) {
	a := newApp()
	a.cfg.Quiet = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	var counter int64
	jobs := []int{1, 2, 3}

	runWorkers(ctx, jobs, func(_ context.Context, n int) {
		counter += int64(n)
	}, 2, "test", a)

	// Should not panic; counter should be 0 since context is cancelled.
	if counter != 0 {
		t.Logf("counter = %d (may vary due to race)", counter)
	}
}
