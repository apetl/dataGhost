// Package app implements the core dataGhost operations, worker pools, and app state.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dataGhost/internal/config"
	"dataGhost/internal/ghost"
	"dataGhost/internal/hash"
	"dataGhost/internal/output"
)

const (
	boundedMapCap      = 1024
	workerQueueSize    = 1000
	progressUpdateFreq = 10
)

// Stats tracks operation statistics with thread-safe atomic operations.
type Stats struct {
	Checked   atomic.Int64
	Corrupted atomic.Int64
	OK        atomic.Int64
	Errors    atomic.Int64
	Skipped   atomic.Int64
	Added     atomic.Int64
	Deleted   atomic.Int64
	Modified  atomic.Int64
	Updated   atomic.Int64
}

// Snapshot returns a read-only snapshot of all statistics.
func (s *Stats) Snapshot() map[string]int64 {
	return map[string]int64{
		"checked":   s.Checked.Load(),
		"corrupted": s.Corrupted.Load(),
		"ok":        s.OK.Load(),
		"errors":    s.Errors.Load(),
		"skipped":   s.Skipped.Load(),
		"added":     s.Added.Load(),
		"deleted":   s.Deleted.Load(),
		"modified":  s.Modified.Load(),
		"updated":   s.Updated.Load(),
	}
}

// workItem represents a file to be processed by a worker.
type workItem struct {
	filePath  string
	ghostPath string
	basePath  string
}

// updateWorkItem represents a ghost file to be updated by a worker.
type updateWorkItem struct {
	ghostPath string
	dirPath   string
}

// boundedMap is a mutex-protected map with a hard capacity cap.
type boundedMap[V any] struct {
	mu  sync.Mutex
	m   map[string]V
	cap int
}

func newBoundedMap[V any](cap int) *boundedMap[V] {
	return &boundedMap[V]{m: make(map[string]V, cap), cap: cap}
}

func (b *boundedMap[V]) loadOrStore(key string, newVal V) V {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v, ok := b.m[key]; ok {
		return v
	}
	if len(b.m) >= b.cap {
		b.m = make(map[string]V, b.cap)
	}
	b.m[key] = newVal
	return newVal
}

func (b *boundedMap[V]) load(key string) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[key]
	return v, ok
}

func (b *boundedMap[V]) store(key string, val V) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.m) >= b.cap {
		b.m = make(map[string]V, b.cap)
	}
	b.m[key] = val
}

// App holds all runtime state for a dataGhost operation.
type App struct {
	Config       config.Config
	Strict       bool
	AlwaysRehash bool
	StartTime    time.Time
	Stats        Stats

	configCache *boundedMap[config.Config]
	ghostMutex  sync.Map
	outputMu    sync.Mutex
}

// NewApp creates a new App with default configuration.
func NewApp() *App {
	cfg := config.DefaultConfig()
	return &App{
		Config:      cfg,
		StartTime:   time.Now(),
		configCache: newBoundedMap[config.Config](boundedMapCap),
	}
}

// getGhostMutex returns the canonical mutex for a given ghost-file path.
func (a *App) getGhostMutex(ghostPath string) *sync.Mutex {
	v, _ := a.ghostMutex.LoadOrStore(ghostPath, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// Logf logs a formatted message unless quiet mode is enabled.
func (a *App) Logf(format string, args ...any) {
	if !a.Config.Quiet {
		a.outputMu.Lock()
		a.clearProgress()
		fmt.Printf(format, args...)
		a.outputMu.Unlock()
	}
}

// PrintProgress renders a progress line to the terminal.
func (a *App) PrintProgress(current, total int64, operation string) {
	if !a.Config.ShowProgress || a.Config.Quiet {
		return
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	fmt.Print("\r\033[K")
	if total > 0 {
		pct := float64(current) / float64(total) * 100
		fmt.Printf("%s[%s] Processing: %d/%d (%.1f%%)%s",
			output.ColorCyan, operation, current, total, pct, output.ColorReset)
	} else {
		fmt.Printf("%s[%s] Processing items: %d%s",
			output.ColorCyan, operation, current, output.ColorReset)
	}
}

func (a *App) clearProgress() {
	if !a.Config.ShowProgress || a.Config.Quiet {
		return
	}
	fmt.Print("\r\033[K")
}

// ── config ───────────────────────────────────────────────────────────────────

// LoadConfig resolves the effective configuration for the target path.
func (a *App) LoadConfig(configFile, targetPath string, useConfig, useStrict bool) error {
	a.Config = config.DefaultConfig()
	a.Strict = useStrict
	if !useConfig {
		return nil
	}
	configPath := configFile
	if configPath == "" {
		abs, err := filepath.Abs(targetPath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for '%s': %w", targetPath, err)
		}
		st, err := os.Stat(abs)
		if err != nil {
			return fmt.Errorf("failed to stat target path '%s': %w", abs, err)
		}
		root := abs
		if !st.IsDir() {
			root = filepath.Dir(abs)
		}
		configPath = filepath.Join(root, ".ghostconf")
	}
	var err error
	a.Config, err = config.LoadConfigFromFile(configPath)
	return err
}

// getConfigForPath returns the effective config for a directory.
func (a *App) getConfigForPath(dirPath string) config.Config {
	if a.Strict {
		return a.Config
	}
	if v, ok := a.configCache.load(dirPath); ok {
		return v
	}
	cfg := a.Config
	if local, err := config.LoadConfigFromFile(filepath.Join(dirPath, ".ghostconf")); err == nil {
		cfg.Ignore = local.Ignore
	}
	return a.configCache.loadOrStore(dirPath, cfg)
}

// IsIgnored checks whether a path should be ignored.
func (a *App) IsIgnored(path, basePath string, isDir bool) bool {
	dir := filepath.Dir(path)
	if isDir {
		dir = path
	}
	return config.IsIgnoredWithConfig(a.getConfigForPath(dir), path, basePath, isDir)
}

// ── operations ───────────────────────────────────────────────────────────────

// AddF adds or updates a single file in its parent .ghost file.
func (a *App) AddF(ctx context.Context, filePath, ghostPath, basePath string) {
	if ctx.Err() != nil {
		return
	}
	if a.IsIgnored(filePath, basePath, false) {
		a.Logf("%s[IGNORE]%s %s\n", output.ColorYellow, output.ColorReset, filePath)
		a.Stats.Skipped.Add(1)
		return
	}

	currentHash, err := hash.CalcHash(filePath, a.Config.Buffer)
	if err != nil {
		a.Logf("%s[ERROR]%s Failed to hash '%s': %v\n", output.ColorRed, output.ColorReset, filePath, err)
		a.Stats.Errors.Add(1)
		return
	}

	st, err := os.Lstat(filePath)
	if err != nil {
		a.Logf("%s[ERROR]%s Failed to access '%s': %v\n", output.ColorRed, output.ColorReset, filePath, err)
		a.Stats.Errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)

	var promptHash string
	var promptFilename string
	shouldPrompt := false
	if !a.Config.Force {
		mu := a.getGhostMutex(ghostPath)
		mu.Lock()
		preData, preErr := ghost.ReadGhost(ghostPath)
		mu.Unlock()
		if preErr == nil {
			if stored, exists := preData[filename]; exists && stored.Blake2b != currentHash {
				shouldPrompt = true
				promptHash = stored.Blake2b
				promptFilename = filename
			}
		} else {
			a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, preErr)
			a.Stats.Errors.Add(1)
			return
		}
	}
	if shouldPrompt {
		if !output.IsStdinInteractive() {
			a.Logf("%s[WARNING]%s '%s' already tracked with a different hash. Skipping overwrite (stdin is not a terminal; use -f to force).\n", output.ColorYellow, output.ColorReset, promptFilename)
			return
		}
		a.outputMu.Lock()
		a.clearProgress()
		fmt.Printf("%s[WARNING]%s '%s' already tracked with a different hash.\n", output.ColorYellow, output.ColorReset, promptFilename)
		fmt.Printf("  Existing: %s\n  Current:  %s\n", promptHash, currentHash)
		fmt.Print("  Overwrite? (y/n): ")
		a.outputMu.Unlock()
		var resp string
		fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			a.Logf("%s[CANCELLED]%s %s\n", output.ColorYellow, output.ColorReset, promptFilename)
			return
		}
	}

	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := ghost.ReadGhost(ghostPath)
	if err != nil {
		a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, err)
		a.Stats.Errors.Add(1)
		return
	}

	if stored, exists := data[filename]; exists {
		if currentHash == stored.Blake2b {
			a.Logf("%s[UNCHANGED]%s %s\n", output.ColorGray, output.ColorReset, filename)
			return
		}
		if shouldPrompt && stored.Blake2b != promptHash {
			a.Logf("%s[WARN]%s Ghost data changed during prompt. Proceeding with update.\n", output.ColorYellow, output.ColorReset)
		}
		a.Stats.Modified.Add(1)
		a.Logf("%s[UPDATED]%s %s\n", output.ColorBlue, output.ColorReset, filename)
	} else {
		a.Stats.Added.Add(1)
		a.Logf("%s[ADDED]%s %s\n", output.ColorGreen, output.ColorReset, filename)
	}

	data[filename] = ghost.FileData{Blake2b: currentHash, Size: st.Size(), Modified: st.ModTime()}
	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, err)
		a.Stats.Errors.Add(1)
	}
}

// DelF removes a single file from its parent .ghost file.
func (a *App) DelF(ctx context.Context, filePath, ghostPath, _ string) {
	if ctx.Err() != nil {
		return
	}
	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := ghost.ReadGhost(ghostPath)
	if err != nil {
		a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, err)
		a.Stats.Errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)
	if _, exists := data[filename]; !exists {
		a.Logf("%s[NOT FOUND]%s '%s' not in ghost database.\n", output.ColorYellow, output.ColorReset, filename)
		return
	}

	delete(data, filename)
	a.Stats.Deleted.Add(1)
	a.Logf("%s[DELETED]%s %s\n", output.ColorRed, output.ColorReset, filename)

	if err := ghost.WriteGhost(data, ghostPath); err != nil {
		a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, err)
		a.Stats.Errors.Add(1)
	}
}

// CheckF verifies a single file against its stored hash.
func (a *App) CheckF(ctx context.Context, filePath, ghostPath, basePath string) {
	if ctx.Err() != nil {
		return
	}
	if a.IsIgnored(filePath, basePath, false) {
		a.Stats.Skipped.Add(1)
		return
	}

	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	data, err := ghost.ReadGhost(ghostPath)
	mu.Unlock()

	if err != nil {
		a.Stats.Errors.Add(1)
		a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, err)
		return
	}

	filename := filepath.Base(filePath)
	stored, exists := data[filename]
	if !exists {
		a.Logf("%s[NOT TRACKED]%s %s\n", output.ColorYellow, output.ColorReset, filename)
		return
	}

	a.Stats.Checked.Add(1)

	st, err := os.Lstat(filePath)
	if err != nil {
		a.Stats.Errors.Add(1)
		a.Logf("%s[ERROR]%s Failed to stat '%s': %v\n", output.ColorRed, output.ColorReset, filePath, err)
		return
	}

	if !a.AlwaysRehash && !ghost.NeedsRehash(st, stored) {
		a.Stats.OK.Add(1)
		a.Logf("%s[OK]%s %s %s(cached)%s\n", output.ColorGreen, output.ColorReset, filename, output.ColorGray, output.ColorReset)
		return
	}

	currentHash, err := hash.CalcHash(filePath, a.Config.Buffer)
	if err != nil {
		a.Stats.Errors.Add(1)
		a.Logf("%s[ERROR]%s %v\n", output.ColorRed, output.ColorReset, err)
		return
	}

	if currentHash == stored.Blake2b {
		a.Stats.OK.Add(1)
		a.Logf("%s[OK]%s %s\n", output.ColorGreen, output.ColorReset, filename)
	} else {
		a.Stats.Corrupted.Add(1)
		a.Logf("%s[CORRUPTED]%s %s\n  Expected: %s\n  Current:  %s\n",
			output.ColorRed, output.ColorReset, filename, stored.Blake2b, currentHash)
	}
}

// ProcessFiles walks path and dispatches each file to operation via a worker pool.
func (a *App) ProcessFiles(ctx context.Context, path string, recursive bool,
	operation func(context.Context, string, string, string), operationName string) error {

	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path is a symbolic link, skipping: '%s'", path)
	}
	if !fi.IsDir() {
		dirPath := filepath.Dir(path)
		operation(ctx, path, filepath.Join(dirPath, ".ghost"), dirPath)
		return nil
	}

	a.Logf("%s[PROCESSING]%s Directory: %s (recursive: %v)\n", output.ColorCyan, output.ColorReset, path, recursive)

	jobChan := make(chan workItem, workerQueueSize)
	var wg sync.WaitGroup
	var processed atomic.Int64

	numWorkers := a.Config.Parallel
	if numWorkers < 1 {
		numWorkers = 1
	}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				if ctx.Err() != nil {
					continue
				}
				operation(ctx, job.filePath, job.ghostPath, job.basePath)
				cur := processed.Add(1)
				if cur%progressUpdateFreq == 0 {
					a.PrintProgress(cur, 0, operationName)
				}
			}
		}()
	}

	dirConfigCache := make(map[string]config.Config)
	getDirCfg := func(dir string) config.Config {
		if c, ok := dirConfigCache[dir]; ok {
			return c
		}
		c := a.getConfigForPath(dir)
		dirConfigCache[dir] = c
		return c
	}

	walkErr := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			a.Logf("%s[ERROR]%s Accessing '%s': %v\n", output.ColorRed, output.ColorReset, filePath, err)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		isDir := d.IsDir()
		if !recursive && isDir && filePath != path {
			return filepath.SkipDir
		}
		if isDir && filePath != path {
			dirCfg := getDirCfg(filePath)
			if config.IsIgnoredWithConfig(dirCfg, filePath, path, true) {
				a.Logf("%s[SKIP DIR]%s %s\n", output.ColorYellow, output.ColorReset, filePath)
				return filepath.SkipDir
			}
			return nil
		}
		if isDir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.Name() == ".ghost" || d.Name() == ".ghostconf" {
			return nil
		}
		dirPath := filepath.Dir(filePath)
		dirCfg := getDirCfg(dirPath)
		if config.IsIgnoredWithConfig(dirCfg, filePath, path, false) {
			a.Stats.Skipped.Add(1)
			return nil
		}
		localGhostPath := filepath.Join(dirPath, ".ghost")
		if !recursive {
			localGhostPath = filepath.Join(path, ".ghost")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case jobChan <- workItem{filePath, localGhostPath, path}:
		}
		return nil
	})

	close(jobChan)
	wg.Wait()
	a.clearProgress()

	if walkErr != nil && walkErr != context.Canceled {
		return fmt.Errorf("error processing directory: %w", walkErr)
	}
	a.Logf("%s[COMPLETED]%s Processed %d file(s)\n", output.ColorGreen, output.ColorReset, processed.Load())
	return nil
}

// cleanGhostFile removes entries for missing files from a single ghost file.
func (a *App) cleanGhostFile(ghostPath string) int64 {
	dirPath := filepath.Dir(ghostPath)
	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := ghost.ReadGhost(ghostPath)
	if err != nil {
		a.Logf("%s[ERROR]%s Failed to read %s: %v\n", output.ColorRed, output.ColorReset, ghostPath, err)
		a.Stats.Errors.Add(1)
		return 0
	}
	removed := 0
	for filename := range data {
		if _, err := os.Lstat(filepath.Join(dirPath, filename)); os.IsNotExist(err) {
			a.Logf("%s[MISSING]%s Removing entry for %s\n", output.ColorYellow, output.ColorReset, filename)
			delete(data, filename)
			removed++
		}
	}
	if removed > 0 {
		if err := ghost.WriteGhost(data, ghostPath); err != nil {
			a.Logf("%s[ERROR]%s Failed to write %s: %v\n", output.ColorRed, output.ColorReset, ghostPath, err)
			a.Stats.Errors.Add(1)
			return 0
		}
	}
	return int64(removed)
}

// Clean removes missing-file entries from .ghost files in a directory tree.
func (a *App) Clean(ctx context.Context, path string, recursive bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("clean command requires a directory path")
	}

	a.Logf("%s[CLEANING]%s Directory: %s\n", output.ColorCyan, output.ColorReset, path)
	var ghostFiles []string

	if err := filepath.WalkDir(path, func(fp string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if !recursive && d.IsDir() && fp != path {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == ".ghost" {
			ghostFiles = append(ghostFiles, fp)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	if len(ghostFiles) == 0 {
		a.Logf("%s[INFO]%s No .ghost files found\n", output.ColorCyan, output.ColorReset)
		return nil
	}

	var totalCleaned int64
	for _, ghostPath := range ghostFiles {
		if ctx.Err() != nil {
			break
		}
		cleaned := a.cleanGhostFile(ghostPath)
		totalCleaned += cleaned
	}

	if totalCleaned > 0 {
		a.Logf("%s[CLEANED]%s Removed %d missing file(s)\n", output.ColorGreen, output.ColorReset, totalCleaned)
	} else {
		a.Logf("%s[OK]%s No missing files found\n", output.ColorGreen, output.ColorReset)
	}
	return nil
}

func (a *App) updateGhostFile(ctx context.Context, job updateWorkItem) {
	if ctx.Err() != nil {
		return
	}
	mu := a.getGhostMutex(job.ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := ghost.ReadGhost(job.ghostPath)
	if err != nil {
		a.Logf("%s[ERROR]%s Failed to read '%s': %v\n", output.ColorRed, output.ColorReset, job.ghostPath, err)
		a.Stats.Errors.Add(1)
		return
	}

	updatedCount := 0
	for filename, fi := range data {
		if fi.Size != 0 || !fi.Modified.IsZero() {
			continue
		}
		filePath := filepath.Join(job.dirPath, filename)
		st, err := os.Lstat(filePath)
		if err != nil {
			a.Logf("%s[WARNING]%s Cannot stat '%s': %v\n", output.ColorYellow, output.ColorReset, filename, err)
			continue
		}
		currentHash, err := hash.CalcHash(filePath, a.Config.Buffer)
		if err != nil {
			a.Logf("%s[ERROR]%s Failed to hash '%s': %v\n", output.ColorRed, output.ColorReset, filename, err)
			a.Stats.Errors.Add(1)
			continue
		}
		if currentHash != fi.Blake2b {
			a.Logf("%s[HASH MISMATCH]%s %s -- cannot update metadata.\n", output.ColorRed, output.ColorReset, filename)
			a.Stats.Corrupted.Add(1)
			continue
		}
		data[filename] = ghost.FileData{Blake2b: fi.Blake2b, Size: st.Size(), Modified: st.ModTime()}
		updatedCount++
		a.Stats.Updated.Add(1)
	}

	if updatedCount > 0 {
		if err := ghost.WriteGhost(data, job.ghostPath); err != nil {
			a.Logf("%s[ERROR]%s Failed to write '%s': %v\n", output.ColorRed, output.ColorReset, job.ghostPath, err)
			a.Stats.Errors.Add(1)
			return
		}
		a.Logf("%s[UPDATED]%s %d metadata update(s) in %s\n", output.ColorGreen, output.ColorReset, updatedCount, job.ghostPath)
	}
}

// Update adds size/modification metadata to legacy .ghost files.
func (a *App) Update(ctx context.Context, path string, recursive bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}
	if !fi.IsDir() && filepath.Base(path) == ".ghost" {
		a.updateGhostFile(ctx, updateWorkItem{ghostPath: path, dirPath: filepath.Dir(path)})
		return nil
	}
	if !fi.IsDir() {
		return fmt.Errorf("path must be a directory or a .ghost file")
	}

	a.Logf("%s[UPDATING]%s Searching for .ghost files in: %s\n", output.ColorCyan, output.ColorReset, path)
	var items []updateWorkItem

	if err := filepath.WalkDir(path, func(fp string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if !recursive && d.IsDir() && fp != path {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == ".ghost" {
			items = append(items, updateWorkItem{ghostPath: fp, dirPath: filepath.Dir(fp)})
		}
		return nil
	}); err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	RunWorkers(ctx, items, a.updateGhostFile, a.Config.Parallel, "update", a)
	a.Logf("%s[COMPLETED]%s Processed %d ghost file(s)\n", output.ColorGreen, output.ColorReset, len(items))
	return nil
}

// PrintSummary renders the final operation summary box.
func (a *App) PrintSummary() {
	elapsed := time.Since(a.StartTime).Round(time.Millisecond)
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.clearProgress()
	fmt.Println()

	const w = 43
	top := output.ColorBlue + "╔" + strings.Repeat("═", w) + "╗" + output.ColorReset
	mid := output.ColorBlue + "╠" + strings.Repeat("═", w) + "╣" + output.ColorReset
	bot := output.ColorBlue + "╚" + strings.Repeat("═", w) + "╝" + output.ColorReset
	bar := output.ColorBlue + "║" + output.ColorReset

	fmt.Println(top)
	title := "OPERATION SUMMARY"
	lp := (w - len(title)) / 2
	rp := w - len(title) - lp
	fmt.Printf("%s%s%s%s%s\n", bar, strings.Repeat(" ", lp), title, strings.Repeat(" ", rp), bar)
	fmt.Println(mid)

	line := func(label, value, vc string) {
		pad := w - len(label) - len(value) - 2
		if pad < 0 {
			pad = 0
		}
		v := value
		if vc != "" {
			v = vc + value + output.ColorReset
		}
		fmt.Printf("%s %s%*s%s %s\n", bar, label, pad, "", v, bar)
	}

	if v := a.Stats.Checked.Load(); v > 0 {
		line("Checked:", fmt.Sprintf("%d", v), output.ColorCyan)
	}
	if v := a.Stats.OK.Load(); v > 0 {
		line("OK:", fmt.Sprintf("%d", v), output.ColorGreen)
	}
	if v := a.Stats.Corrupted.Load(); v > 0 {
		line("Corrupted:", fmt.Sprintf("%d", v), output.ColorRed)
	}
	if v := a.Stats.Added.Load(); v > 0 {
		line("Added:", fmt.Sprintf("%d", v), output.ColorGreen)
	}
	if v := a.Stats.Modified.Load(); v > 0 {
		line("Modified:", fmt.Sprintf("%d", v), output.ColorBlue)
	}
	if v := a.Stats.Updated.Load(); v > 0 {
		line("Updated:", fmt.Sprintf("%d", v), output.ColorGreen)
	}
	if v := a.Stats.Deleted.Load(); v > 0 {
		line("Deleted:", fmt.Sprintf("%d", v), output.ColorRed)
	}
	if v := a.Stats.Skipped.Load(); v > 0 {
		line("Skipped:", fmt.Sprintf("%d", v), output.ColorYellow)
	}
	if v := a.Stats.Errors.Load(); v > 0 {
		line("Errors:", fmt.Sprintf("%d", v), output.ColorRed)
	}
	line("Duration:", elapsed.String(), "")
	fmt.Println(bot)
}

// RunWorkers dispatches jobs to a pool of goroutines with progress reporting.
func RunWorkers[T any](ctx context.Context, jobs []T, workerFunc func(context.Context, T), numWorkers int, operationName string, a *App) {
	if len(jobs) == 0 {
		return
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	jobChan := make(chan T, workerQueueSize)
	var wg sync.WaitGroup
	var processed atomic.Int64
	totalJobs := int64(len(jobs))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				if ctx.Err() != nil {
					continue
				}
				workerFunc(ctx, job)
				cur := processed.Add(1)
				if cur%progressUpdateFreq == 0 {
					a.PrintProgress(cur, totalJobs, operationName)
				}
			}
		}()
	}

	for _, job := range jobs {
		select {
		case <-ctx.Done():
			goto done
		case jobChan <- job:
		}
	}
done:
	close(jobChan)
	wg.Wait()
	a.clearProgress()
}
