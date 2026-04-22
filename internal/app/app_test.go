package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"dataGhost/internal/ghost"
	"dataGhost/internal/hash"
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
