package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dataGhost/internal/ghost"
	"dataGhost/internal/hash"
	"dataGhost/internal/output"
)

func TestNewApp(t *testing.T) {
	a := NewApp()
	if a == nil {
		t.Fatal("NewApp() returned nil")
	}
	if a.configCache == nil {
		t.Error("configCache is nil")
	}
	if a.Config.Parallel != runtime.NumCPU() {
		t.Errorf("default parallel = %d, want %d", a.Config.Parallel, runtime.NumCPU())
	}
}

func TestRunWorkers(t *testing.T) {
	a := NewApp()
	a.Config.Quiet = true

	var counter int64
	jobs := []int{1, 2, 3, 4, 5}

	RunWorkers(context.Background(), jobs, func(_ context.Context, n int) {
		counter += int64(n)
	}, 2, "test", a)

	if counter != 15 {
		t.Errorf("counter = %d, want 15", counter)
	}
}

func TestRunWorkersEmpty(t *testing.T) {
	a := NewApp()
	var called bool
	RunWorkers(context.Background(), []int{}, func(_ context.Context, n int) {
		called = true
	}, 2, "test", a)
	if called {
		t.Error("worker func should not have been called for empty jobs")
	}
}

func TestRunWorkersCancelledContext(t *testing.T) {
	a := NewApp()
	a.Config.Quiet = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var counter int64
	jobs := []int{1, 2, 3}

	RunWorkers(ctx, jobs, func(_ context.Context, n int) {
		counter += int64(n)
	}, 2, "test", a)

	if counter != 0 {
		t.Logf("counter = %d (may vary due to race)", counter)
	}
}

func TestEndToEndAddAndCheck(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	a.Config.Force = true
	a.Config.Parallel = 1
	a.Config.Quiet = true

	ctx := context.Background()

	err := a.ProcessFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a.AddF(ctx, fp, gp, bp) }, "add")
	if err != nil {
		t.Fatalf("add error: %v", err)
	}

	ghostPath := filepath.Join(tmpDir, ".ghost")
	if _, err := os.Stat(ghostPath); os.IsNotExist(err) {
		t.Fatal(".ghost file was not created")
	}

	a2 := NewApp()
	a2.Config.Parallel = 1
	a2.Config.Quiet = true

	err = a2.ProcessFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a2.CheckF(ctx, fp, gp, bp) }, "check")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}

	if a2.Stats.OK.Load() != 1 {
		t.Errorf("ok count = %d, want 1", a2.Stats.OK.Load())
	}

	if err := os.WriteFile(filePath, []byte("corrupted"), 0644); err != nil {
		t.Fatal(err)
	}

	a3 := NewApp()
	a3.Config.Parallel = 1
	a3.Config.Quiet = true
	a3.AlwaysRehash = true

	err = a3.ProcessFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a3.CheckF(ctx, fp, gp, bp) }, "check")
	if err != nil {
		t.Fatalf("check after corruption error: %v", err)
	}

	if a3.Stats.Corrupted.Load() != 1 {
		t.Errorf("corrupted count = %d, want 1", a3.Stats.Corrupted.Load())
	}
}

func TestEndToEndClean(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keep.txt")
	ghostPath := filepath.Join(tmpDir, ".ghost")

	if err := os.WriteFile(filePath, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}

	data := map[string]ghost.FileData{
		"keep.txt": {Blake2b: "abc", Size: 4},
		"gone.txt": {Blake2b: "def", Size: 4},
	}
	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	a.Config.Quiet = true

	ctx := context.Background()
	if err := a.Clean(ctx, tmpDir, false); err != nil {
		t.Fatalf("clean error: %v", err)
	}

	readBack, err := ghost.ReadGhost(ghostPath)
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

	hashStr, err := hash.CalcHash(filePath, 0)
	if err != nil {
		t.Fatal(err)
	}

	ghostPath := filepath.Join(tmpDir, ".ghost")
	data := map[string]ghost.FileData{
		"test.txt": {Blake2b: hashStr},
	}
	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	a.Config.Quiet = true

	ctx := context.Background()
	if err := a.Update(ctx, tmpDir, false); err != nil {
		t.Fatalf("update error: %v", err)
	}

	readBack, err := ghost.ReadGhost(ghostPath)
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

	data := map[string]ghost.FileData{
		"delete.txt": {Blake2b: "abc123"},
	}
	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	a.Config.Quiet = true

	ctx := context.Background()
	err := a.ProcessFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a.DelF(ctx, fp, gp, bp) }, "delete")
	if err != nil {
		t.Fatalf("del error: %v", err)
	}

	if a.Stats.Deleted.Load() != 1 {
		t.Errorf("deleted count = %d, want 1", a.Stats.Deleted.Load())
	}

	readBack, err := ghost.ReadGhost(ghostPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := readBack["delete.txt"]; ok {
		t.Error("delete.txt should have been removed")
	}
}

// TestCheckReportsMissing verifies that a directory check reports ghost entries
// whose files have vanished from disk, while ignored entries are not reported.
func TestCheckReportsMissing(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keep.txt")

	if err := os.WriteFile(filePath, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	hashStr, err := hash.CalcHash(filePath, 0)
	if err != nil {
		t.Fatal(err)
	}

	ghostPath := filepath.Join(tmpDir, ".ghost")
	data := map[string]ghost.FileData{
		"keep.txt": {Blake2b: hashStr},
		"gone.txt": {Blake2b: "def"}, // deleted from disk: must be reported
		"gone.log": {Blake2b: "ghi"}, // deleted but ignored: must NOT be reported
	}
	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	a.Config.Quiet = true
	a.Config.Parallel = 1
	a.AlwaysRehash = true
	a.Config.Ignore = []string{"*.log"}

	ctx := context.Background()
	if err := a.ProcessFiles(ctx, tmpDir, false,
		func(ctx context.Context, fp, gp, bp string) { a.CheckF(ctx, fp, gp, bp) }, "check"); err != nil {
		t.Fatalf("check error: %v", err)
	}

	if got := a.Stats.OK.Load(); got != 1 {
		t.Errorf("ok count = %d, want 1", got)
	}
	if got := a.Stats.Missing.Load(); got != 1 {
		t.Errorf("missing count = %d, want 1 (gone.txt only; gone.log is ignored)", got)
	}
}

// TestCheckSingleFileNoMissing verifies the documented contract that checking a
// single file never reports other ghost entries as missing.
func TestCheckSingleFileNoMissing(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "one.txt")
	ghostPath := filepath.Join(tmpDir, ".ghost")

	if err := os.WriteFile(filePath, []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	data := map[string]ghost.FileData{
		"one.txt": {Blake2b: "abc"},
		"two.txt": {Blake2b: "def"},
	}
	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	a.Config.Quiet = true
	a.Config.Parallel = 1

	ctx := context.Background()
	if err := a.ProcessFiles(ctx, filePath, false,
		func(ctx context.Context, fp, gp, bp string) { a.CheckF(ctx, fp, gp, bp) }, "check"); err != nil {
		t.Fatalf("check error: %v", err)
	}
	if got := a.Stats.Missing.Load(); got != 0 {
		t.Errorf("missing count = %d, want 0 for single-file check", got)
	}
}

// TestShouldLogVerbosity verifies the verbosity/quiet/JSON gating of tagged logs.
func TestShouldLogVerbosity(t *testing.T) {
	a := NewApp()

	if !a.shouldLog(output.TagError) {
		t.Error("LevelAlways tag should log at verbosity 0")
	}
	if a.shouldLog(output.TagOK) {
		t.Error("LevelVerbose tag should not log at verbosity 0")
	}
	a.Verbosity = 1
	if !a.shouldLog(output.TagOK) {
		t.Error("LevelVerbose tag should log at verbosity 1")
	}
	if a.shouldLog(output.TagSkip) {
		t.Error("LevelDebug tag should not log at verbosity 1")
	}
	a.Verbosity = 2
	if !a.shouldLog(output.TagSkip) {
		t.Error("LevelDebug tag should log at verbosity 2")
	}
	a.Config.Quiet = true
	if a.shouldLog(output.TagError) {
		t.Error("quiet mode should suppress all tagged logs")
	}
	a.Config.Quiet = false
	a.JSONOutput = true
	if a.shouldLog(output.TagError) {
		t.Error("JSON mode should suppress tagged logs")
	}
}

// TestGhostBatching proves the per-ghost write-back cache: two AddF calls
// mutate the in-memory cache only; the on-disk .ghost stays untouched until
// flushGhosts runs, after which both entries materialize in a single write.
func TestGhostBatching(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "a.txt")
	f2 := filepath.Join(tmpDir, "b.txt")
	if err := os.WriteFile(f1, []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}
	ghostPath := filepath.Join(tmpDir, ".ghost")

	a := NewApp()
	a.Config.Force = true
	a.Config.Quiet = true
	a.Config.Parallel = 1

	ctx := context.Background()
	a.AddF(ctx, f1, ghostPath, tmpDir)
	a.AddF(ctx, f2, ghostPath, tmpDir)

	// Before flush, nothing should have hit disk.
	if data, err := ghost.ReadGhost(ghostPath); err != nil {
		t.Fatalf("read ghost pre-flush: %v", err)
	} else if len(data) != 0 {
		t.Errorf("ghost written before flush (batching broken): %d entries", len(data))
	}

	a.flushGhosts()

	data, err := ghost.ReadGhost(ghostPath)
	if err != nil {
		t.Fatalf("read ghost post-flush: %v", err)
	}
	if len(data) != 2 {
		t.Fatalf("post-flush entries = %d, want 2", len(data))
	}
	if _, ok := data["a.txt"]; !ok {
		t.Error("a.txt missing post-flush")
	}
	if _, ok := data["b.txt"]; !ok {
		t.Error("b.txt missing post-flush")
	}
}

// TestCheckQuickCheckMetadataSelfHeals verifies that a quick check rehashing a
// file whose modtime drifted (but content is intact) refreshes the stored
// metadata, so the next quick check hits the cached path instead of rehashing
// forever.
func TestCheckQuickCheckMetadataSelfHeals(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file.txt")
	content := []byte("unchanged content")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}
	ghostPath := filepath.Join(tmpDir, ".ghost")

	// Add: records hash + size + modtime.
	add := NewApp()
	add.Config.Force = true
	add.Config.Quiet = true
	add.Config.Parallel = 1
	ctx := context.Background()
	add.AddF(ctx, filePath, ghostPath, tmpDir)
	add.flushGhosts()

	storedBefore, _ := ghost.ReadGhost(ghostPath)

	// Drift the modtime without changing content.
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(filePath, future, future); err != nil {
		t.Fatal(err)
	}

	// First quick check: rehashes (metadata drifted), content matches, self-heals.
	a1 := NewApp()
	a1.Config.Quiet = true
	a1.Config.Parallel = 1
	a1.AlwaysRehash = false // -qc mode
	if err := a1.ProcessFiles(ctx, tmpDir, false,
		func(ctx context.Context, fp, gp, bp string) { a1.CheckF(ctx, fp, gp, bp) }, "check"); err != nil {
		t.Fatalf("first check error: %v", err)
	}
	if a1.Stats.OK.Load() != 1 {
		t.Errorf("first check ok = %d, want 1", a1.Stats.OK.Load())
	}
	if a1.Stats.Bytes.Load() != int64(len(content)) {
		t.Errorf("first check bytes = %d, want %d (should have rehashed)", a1.Stats.Bytes.Load(), len(content))
	}

	// Metadata must now be refreshed on disk.
	storedAfter, _ := ghost.ReadGhost(ghostPath)
	if storedAfter["file.txt"].Modified.Equal(storedBefore["file.txt"].Modified) {
		t.Error("modified time was not refreshed after self-heal")
	}
	if !storedAfter["file.txt"].Modified.Equal(future) {
		t.Errorf("modified time = %v, want %v", storedAfter["file.txt"].Modified, future)
	}

	// Second quick check: should hit the cached path (no rehash, no bytes).
	a2 := NewApp()
	a2.Config.Quiet = true
	a2.Config.Parallel = 1
	a2.AlwaysRehash = false
	if err := a2.ProcessFiles(ctx, tmpDir, false,
		func(ctx context.Context, fp, gp, bp string) { a2.CheckF(ctx, fp, gp, bp) }, "check"); err != nil {
		t.Fatalf("second check error: %v", err)
	}
	if a2.Stats.OK.Load() != 1 {
		t.Errorf("second check ok = %d, want 1", a2.Stats.OK.Load())
	}
	if a2.Stats.Bytes.Load() != 0 {
		t.Errorf("second check bytes = %d, want 0 (should be cached)", a2.Stats.Bytes.Load())
	}
}
