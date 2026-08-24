// Copyright (c) 2026 apetl.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package app implements the core dataGhost operations, worker pools, and app state.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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
	boundedMapCap    = 1024
	workerQueueSize  = 1000
	spinnerThreshold = 128 << 20 // files larger than this get an activity spinner
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
	Missing   atomic.Int64
	Untracked atomic.Int64
	ModeDrift atomic.Int64
	Bytes     atomic.Int64
}

// Snapshot returns a read-only snapshot of all statistics.
func (s *Stats) Snapshot() map[string]int64 {
	return map[string]int64{
		"checked":    s.Checked.Load(),
		"corrupted":  s.Corrupted.Load(),
		"ok":         s.OK.Load(),
		"errors":     s.Errors.Load(),
		"skipped":    s.Skipped.Load(),
		"added":      s.Added.Load(),
		"deleted":    s.Deleted.Load(),
		"modified":   s.Modified.Load(),
		"updated":    s.Updated.Load(),
		"missing":    s.Missing.Load(),
		"untracked":  s.Untracked.Load(),
		"mode_drift": s.ModeDrift.Load(),
		"bytes":      s.Bytes.Load(),
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
		// Evict one arbitrary entry instead of clearing the entire map.
		for k := range b.m {
			delete(b.m, k)
			break
		}
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

// App holds all runtime state for a dataGhost operation.
type App struct {
	Config       config.Config
	Strict       bool
	AlwaysRehash bool
	DryRun       bool
	JSONOutput   bool
	Verbosity    int
	RawBytes     bool
	StartTime    time.Time
	Stats        Stats

	configCache *boundedMap[config.Config]
	ghosts      sync.Map // ghostPath -> *ghostState (per-ghost write-back cache)
	outputMu    sync.Mutex
	currentFile atomic.Value // basename of the file currently being processed
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

// ghostState is the in-memory write-back cache entry for one .ghost file. It
// coalesces per-file mutations so a directory of N files produces at most one
// parse and one write per run instead of N of each.
type ghostState struct {
	mu        sync.Mutex
	path      string
	data      map[string]ghost.FileData
	loadErr   error // cached load error; nil on success or never-loaded
	loaded    bool
	dirty     bool // real mutation (add/del): flush failure is a hard error
	metaDirty bool // only metadata refreshed: flush failure tolerated (read-only media)
}

// getGhostState returns the canonical cache entry for a ghost path.
func (a *App) getGhostState(ghostPath string) *ghostState {
	v, _ := a.ghosts.LoadOrStore(ghostPath, &ghostState{path: ghostPath})
	return v.(*ghostState)
}

// ensureGhostLoaded populates st.data from disk once; subsequent calls return
// the cached result. Caller must hold st.mu.
func (a *App) ensureGhostLoaded(st *ghostState) error {
	if st.loaded {
		return st.loadErr
	}
	st.loaded = true
	data, err := ghost.ReadGhost(st.path)
	if err != nil {
		st.data = make(map[string]ghost.FileData)
		st.loadErr = err
		return err
	}
	st.data = data
	return nil
}

// snapshotGhostData returns a copy of a cached ghost's data, or (nil,false) if
// the ghost was never loaded during this run. Used by reportMissing so the
// missing-detection pass does not re-parse disk.
func (a *App) snapshotGhostData(ghostPath string) (map[string]ghost.FileData, bool) {
	v, ok := a.ghosts.Load(ghostPath)
	if !ok {
		return nil, false
	}
	st := v.(*ghostState)
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.loaded {
		return nil, false
	}
	cp := make(map[string]ghost.FileData, len(st.data))
	for k, fd := range st.data {
		cp[k] = fd
	}
	return cp, true
}

// flushGhosts writes every dirty cache entry back to disk. Called after all
// workers have drained so there is no contention on ghostState.mu. Lock order
// is ghostState.mu -> outputMu (via Logt on error); no path acquires them in
// the reverse order, so this is deadlock-free.
func (a *App) flushGhosts() {
	a.ghosts.Range(func(_, v any) bool {
		st := v.(*ghostState)
		st.mu.Lock()
		defer st.mu.Unlock()
		if !st.loaded || (!st.dirty && !st.metaDirty) {
			return true
		}
		hadRealMutation := st.dirty
		if err := ghost.WriteGhost(st.data, st.path); err != nil {
			if hadRealMutation {
				a.Stats.Errors.Add(1)
				a.Logt(output.TagError, "Failed to write %s: %v\n", st.path, err)
			} else {
				// Metadata self-heal failed — most likely read-only media.
				// Tolerate so check stays usable there.
				a.Logt(output.TagRefresh, "Could not refresh metadata in %s: %v\n", st.path, err)
			}
			return true
		}
		st.dirty = false
		st.metaDirty = false
		return true
	})
}

// ── logging ──────────────────────────────────────────────────────────────────

// shouldLog reports whether a tagged message passes the output gates.
func (a *App) shouldLog(tag output.TagSpec) bool {
	if a.JSONOutput || a.Config.Quiet {
		return false
	}
	return tag.Level <= a.Verbosity
}

// Logt logs a tagged, formatted message. Tags carry their own color and
// verbosity level; see the tag registry in internal/output.
func (a *App) Logt(tag output.TagSpec, format string, args ...any) {
	if !a.shouldLog(tag) {
		return
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.clearProgressLocked()
	fmt.Printf("%s %s", tag.String(), fmt.Sprintf(format, args...))
}

// Logf logs an untagged formatted message unless quiet mode is enabled.
func (a *App) Logf(format string, args ...any) {
	if a.Config.Quiet || a.JSONOutput {
		return
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.clearProgressLocked()
	fmt.Printf(format, args...)
}

// JSONLog emits a structured JSON event when JSON output mode is enabled.
func (a *App) JSONLog(event map[string]any) {
	if !a.JSONOutput {
		return
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	b, _ := json.Marshal(event)
	fmt.Println(string(b))
}

// progressOn reports whether the progress bar may be rendered.
func (a *App) progressOn() bool {
	return a.Config.ShowProgress && !a.Config.Quiet && !a.JSONOutput && output.StdoutIsTTY
}

// PrintProgress renders a progress bar to the terminal.
func (a *App) PrintProgress(current, total int64, operation string) {
	if !a.progressOn() {
		return
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	elapsed := time.Since(a.StartTime)
	var rate float64
	if elapsed > 0 {
		rate = float64(a.Stats.Bytes.Load()) / elapsed.Seconds()
	}
	file, _ := a.currentFile.Load().(string)
	fmt.Print("\r\033[K")
	fmt.Print(output.RenderProgress(output.ProgressState{
		Op:          operation,
		Current:     current,
		Total:       total,
		BytesPerSec: rate,
		Elapsed:     elapsed,
		File:        file,
	}))
}

func (a *App) clearProgressLocked() {
	if !a.progressOn() {
		return
	}
	fmt.Print("\r\033[K")
}

func (a *App) clearProgress() {
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.clearProgressLocked()
}

// ── config ───────────────────────────────────────────────────────────────────

// LoadConfig resolves the effective configuration for the target path.
// Layering (low to high priority): built-in defaults, the user-level global
// config (GlobalConfigPath), then the explicit local config (-c/-cf). Keys
// absent from a higher layer keep the value set by the layer below.
func (a *App) LoadConfig(configFile, targetPath string, useConfig, useStrict bool) error {
	a.Config = config.DefaultConfig()
	a.Strict = useStrict

	// Layer 1: user-level global config, applied to every run. Absence is
	// normal; a parse/validation error is reported because it affects every
	// invocation.
	if gp, err := config.GlobalConfigPath(); err == nil {
		if gerr := config.LoadConfigInto(&a.Config, gp); gerr != nil {
			return fmt.Errorf("global config %s: %w", gp, gerr)
		}
	}

	if !useConfig {
		return nil
	}

	// Layer 2: explicit local config, overriding the global values.
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
	return config.LoadConfigInto(&a.Config, configPath)
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
	// Walk up the directory tree to find the nearest .ghostconf.
	for dir := dirPath; ; dir = filepath.Dir(dir) {
		ghostConfPath := filepath.Join(dir, ".ghostconf")
		if _, err := os.Stat(ghostConfPath); err == nil {
			if local, err := config.LoadConfigFromFile(ghostConfPath); err == nil {
				cfg.Ignore = local.Ignore
				break
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
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
		a.Logt(output.TagIgnore, "%s", filePath)
		a.Stats.Skipped.Add(1)
		return
	}

	currentHash, err := hash.CalcHash(filePath, a.Config.Buffer)
	if err != nil {
		a.Logt(output.TagError, "Failed to hash '%s': %v", filePath, err)
		a.Stats.Errors.Add(1)
		return
	}

	st, err := os.Lstat(filePath)
	if err != nil {
		a.Logt(output.TagError, "Failed to access '%s': %v", filePath, err)
		a.Stats.Errors.Add(1)
		return
	}
	a.Stats.Bytes.Add(st.Size())

	filename := filepath.Base(filePath)

	var promptHash string
	var promptFilename string
	shouldPrompt := false
	if !a.Config.Force {
		gs := a.getGhostState(ghostPath)
		gs.mu.Lock()
		if err := a.ensureGhostLoaded(gs); err != nil {
			gs.mu.Unlock()
			a.Logt(output.TagError, "%v", err)
			a.Stats.Errors.Add(1)
			return
		}
		if stored, exists := gs.data[filename]; exists && stored.Blake2b != currentHash {
			shouldPrompt = true
			promptHash = stored.Blake2b
			promptFilename = filename
		}
		gs.mu.Unlock()
	}
	if shouldPrompt {
		if !output.IsStdinInteractive() {
			a.Logt(output.TagWarning, "'%s' already tracked with a different hash. Skipping overwrite (stdin is not a terminal; use -f to force).\n", promptFilename)
			return
		}
		a.outputMu.Lock()
		a.clearProgressLocked()
		fmt.Printf("%s '%s' already tracked with a different hash.\n", output.TagWarning.String(), promptFilename)
		fmt.Printf("  Existing: %s\n  Current:  %s\n", promptHash, currentHash)
		fmt.Print("  Overwrite? (y/n): ")
		a.outputMu.Unlock()
		var resp string
		fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			a.Logt(output.TagCancelled, "%s\n", promptFilename)
			return
		}
	}

	gs := a.getGhostState(ghostPath)
	gs.mu.Lock()
	defer gs.mu.Unlock()

	if err := a.ensureGhostLoaded(gs); err != nil {
		a.Logt(output.TagError, "%v\n", err)
		a.Stats.Errors.Add(1)
		return
	}

	if stored, exists := gs.data[filename]; exists {
		if currentHash == stored.Blake2b {
			a.Logt(output.TagUnchanged, "%s\n", filename)
			return
		}
		if shouldPrompt && stored.Blake2b != promptHash {
			a.Logt(output.TagWarning, "Ghost data changed during prompt. Proceeding with update.\n")
		}
		a.Stats.Modified.Add(1)
		a.Logt(output.TagUpdated, "%s\n", filename)
	} else {
		a.Stats.Added.Add(1)
		a.Logt(output.TagAdded, "%s\n", filename)
	}

	fd := ghost.FileData{Blake2b: currentHash, Size: st.Size(), Modified: st.ModTime()}
	if a.Config.TrackMode {
		fd.Mode = fmt.Sprintf("%04o", st.Mode().Perm())
	}
	gs.data[filename] = fd
	if a.DryRun {
		a.Logt(output.TagDryRun, "Would write %s to %s\n", filename, ghostPath)
		a.JSONLog(map[string]any{
			"event":      "dry_run",
			"operation":  "add",
			"file":       filename,
			"ghost_path": ghostPath,
			"hash":       currentHash,
			"size":       st.Size(),
		})
		return
	}
	gs.dirty = true
}

// DelF removes a single file from its parent .ghost file.
func (a *App) DelF(ctx context.Context, filePath, ghostPath, _ string) {
	if ctx.Err() != nil {
		return
	}
	gs := a.getGhostState(ghostPath)
	gs.mu.Lock()
	defer gs.mu.Unlock()

	if err := a.ensureGhostLoaded(gs); err != nil {
		a.Logt(output.TagError, "%v\n", err)
		a.Stats.Errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)
	if _, exists := gs.data[filename]; !exists {
		a.Logt(output.TagNotFound, "'%s' is not tracked in %s — nothing to delete\n", filename, ghostPath)
		return
	}

	delete(gs.data, filename)
	a.Stats.Deleted.Add(1)
	a.Logt(output.TagDeleted, "%s\n", filename)
	a.JSONLog(map[string]any{
		"event":      "deleted",
		"file":       filename,
		"ghost_path": ghostPath,
	})

	if a.DryRun {
		a.Logt(output.TagDryRun, "Would remove %s from %s\n", filename, ghostPath)
		return
	}
	gs.dirty = true
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

	gs := a.getGhostState(ghostPath)
	gs.mu.Lock()
	if err := a.ensureGhostLoaded(gs); err != nil {
		gs.mu.Unlock()
		a.Stats.Errors.Add(1)
		a.Logt(output.TagError, "%v\n", err)
		return
	}
	filename := filepath.Base(filePath)
	stored, exists := gs.data[filename]
	gs.mu.Unlock()

	if !exists {
		a.Stats.Untracked.Add(1)
		a.Logt(output.TagNotTracked, "%s\n", filename)
		a.JSONLog(map[string]any{
			"event":      "untracked",
			"file":       filename,
			"ghost_path": ghostPath,
		})
		return
	}

	a.Stats.Checked.Add(1)

	st, err := os.Lstat(filePath)
	if err != nil {
		a.Stats.Errors.Add(1)
		a.Logt(output.TagError, "Failed to stat '%s': %v\n", filePath, err)
		return
	}

	// Mode drift is a non-corrupting caution: permission bits changed without
	// the content changing (e.g. an executable bit silently dropped). Checked
	// in both quick and full modes so a chmod that preserves mtime is caught.
	if a.Config.TrackMode && stored.Mode != "" {
		if curMode := fmt.Sprintf("%04o", st.Mode().Perm()); curMode != stored.Mode {
			a.Stats.ModeDrift.Add(1)
			a.Logt(output.TagModeDrift, "%s %s -> %s\n", filename, stored.Mode, curMode)
			a.JSONLog(map[string]any{
				"event":        "mode_drift",
				"file":         filename,
				"ghost_path":   ghostPath,
				"stored_mode":  stored.Mode,
				"current_mode": curMode,
			})
		}
	}

	if !a.AlwaysRehash && !ghost.NeedsRehash(st, stored) {
		a.Stats.OK.Add(1)
		a.Logt(output.TagOK, "%s %s(cached)%s\n", filename, output.ColorGray, output.ColorReset)
		return
	}

	currentHash, err := hash.CalcHash(filePath, a.Config.Buffer)
	if err != nil {
		a.Stats.Errors.Add(1)
		a.Logt(output.TagError, "%v\n", err)
		return
	}
	a.Stats.Bytes.Add(st.Size())

	if currentHash != stored.Blake2b {
		a.Stats.Corrupted.Add(1)
		a.Logt(output.TagCorrupted, "%s\n  Expected: %s\n  Current:  %s\n",
			filename, stored.Blake2b, currentHash)
		return
	}

	// Content intact.
	a.Stats.OK.Add(1)
	a.Logt(output.TagOK, "%s\n", filename)

	// Self-heal: a quick check rehashes only when size/modtime drifted. If
	// the content still matches, refresh the stored metadata so the next
	// quick check can skip the rehash. Without this the file would rehash
	// on every run, degrading -qc to a full check permanently. Tolerated on
	// read-only media (flush failure is logged at debug, not fatal).
	if !a.AlwaysRehash && ghost.NeedsRehash(st, stored) && !a.DryRun {
		gs.mu.Lock()
		gs.data[filename] = ghost.FileData{Blake2b: stored.Blake2b, Size: st.Size(), Modified: st.ModTime(), Mode: stored.Mode}
		gs.metaDirty = true
		gs.mu.Unlock()
		a.Logt(output.TagRefresh, "%s metadata refreshed\n", filename)
	}
}

// walkEligible walks path and invokes onFile for every file eligible for
// processing, along with its resolved ghost path. onDir fires for each
// non-skipped subdirectory, onMeta for .ghost/.ghostconf files. The same
// walker backs both the counting pre-pass and the dispatch pass so their
// filtering logic can never diverge; logOutput silences per-path logs
// during the counting pass.
func (a *App) walkEligible(ctx context.Context, path string, recursive bool, logOutput bool,
	onFile func(filePath, ghostPath string, d fs.DirEntry),
	onDir func(dirPath string),
	onMeta func(filePath string),
) error {
	dirConfigCache := make(map[string]config.Config)
	getDirCfg := func(dir string) config.Config {
		if c, ok := dirConfigCache[dir]; ok {
			return c
		}
		c := a.getConfigForPath(dir)
		dirConfigCache[dir] = c
		return c
	}

	return filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			if logOutput {
				a.Logt(output.TagError, "Accessing '%s': %v\n", filePath, err)
			}
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
				if logOutput {
					a.Logt(output.TagSkipDir, "%s\n", filePath)
				}
				return filepath.SkipDir
			}
			if onDir != nil {
				onDir(filePath)
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
			if onMeta != nil {
				onMeta(filePath)
			}
			return nil
		}
		dirPath := filepath.Dir(filePath)
		dirCfg := getDirCfg(dirPath)
		if config.IsIgnoredWithConfig(dirCfg, filePath, path, false) {
			a.Stats.Skipped.Add(1)
			if logOutput {
				a.Logt(output.TagIgnore, "%s\n", filePath)
			}
			return nil
		}
		localGhostPath := filepath.Join(dirPath, ".ghost")
		if !recursive {
			localGhostPath = filepath.Join(path, ".ghost")
		}
		if onFile != nil {
			onFile(filePath, localGhostPath, d)
		}
		return nil
	})
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
		var sp *output.Spinner
		if a.progressOn() && fi.Size() >= spinnerThreshold {
			sp = output.NewSpinner(&a.outputMu,
				fmt.Sprintf("Hashing %s (%s)", filepath.Base(path), output.HumanBytes(fi.Size())))
			sp.Start()
		}
		operation(ctx, path, filepath.Join(dirPath, ".ghost"), dirPath)
		if sp != nil {
			sp.Stop()
		}
		a.flushGhosts()
		return nil
	}

	a.Logt(output.TagProcessing, "Directory: %s (recursive: %v)\n", path, recursive)

	// Counting pre-pass: gives the progress bar a real total. Stat-free and
	// cheap compared to hashing; skipped entirely when progress is disabled.
	var total int64
	if a.progressOn() {
		_ = a.walkEligible(ctx, path, recursive, false,
			func(_, _ string, _ fs.DirEntry) { total++ }, nil, nil)
	}

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
				a.currentFile.Store(filepath.Base(job.filePath))
				operation(ctx, job.filePath, job.ghostPath, job.basePath)
				cur := processed.Add(1)
				if cur%10 == 0 {
					a.PrintProgress(cur, total, operationName)
				}
			}
		}()
	}

	// seen tracks dispatched filenames per ghost file so that a check pass can
	// afterwards report tracked entries whose files have vanished from disk.
	var seen map[string]map[string]struct{}
	if operationName == "check" {
		seen = make(map[string]map[string]struct{})
	}
	sawGhost := false

	walkErr := a.walkEligible(ctx, path, recursive, true,
		func(filePath, ghostPath string, d fs.DirEntry) {
			if seen != nil {
				if seen[ghostPath] == nil {
					seen[ghostPath] = make(map[string]struct{})
				}
				seen[ghostPath][d.Name()] = struct{}{}
			}
			select {
			case <-ctx.Done():
			case jobChan <- workItem{filePath, ghostPath, path}:
			}
		},
		func(dirPath string) {
			rel, err := filepath.Rel(path, dirPath)
			if err != nil {
				rel = dirPath
			}
			a.Logt(output.TagDir, "%s\n", rel)
		},
		func(string) { sawGhost = true },
	)

	close(jobChan)
	wg.Wait()
	a.clearProgress()
	// Flush the write-back cache before reporting or returning: this writes
	// every mutated .ghost once, and on cancel it preserves completed work.
	a.flushGhosts()

	if walkErr != nil && walkErr != context.Canceled {
		return fmt.Errorf("error processing directory: %w", walkErr)
	}

	if operationName == "check" && ctx.Err() == nil {
		if !sawGhost {
			hintCmd := "dataGhost add"
			if recursive {
				hintCmd += " -r"
			}
			a.Logt(output.TagHint, "No .ghost found under %s — run '%s %s' to start tracking.\n", path, hintCmd, path)
		}
		a.reportMissing(ctx, seen, path)
	}

	a.Logt(output.TagCompleted, "Processed %d file(s)\n", processed.Load())
	return nil
}

// reportMissing diffs ghost entries against the files seen during a check walk
// and reports tracked files that no longer exist on disk.
func (a *App) reportMissing(ctx context.Context, seen map[string]map[string]struct{}, root string) {
	if len(seen) == 0 {
		return
	}
	ghostPaths := make([]string, 0, len(seen))
	for gp := range seen {
		ghostPaths = append(ghostPaths, gp)
	}
	sort.Strings(ghostPaths)

	for _, gp := range ghostPaths {
		if ctx.Err() != nil {
			return
		}
		data, ok := a.snapshotGhostData(gp)
		if !ok {
			continue // read errors were already reported by the check workers
		}
		dirPath := filepath.Dir(gp)
		var missing []string
		for name := range data {
			if _, ok := seen[gp][name]; ok {
				continue
			}
			// A tracked file that matches the ignore rules was never dispatched;
			// do not report it as missing.
			if a.IsIgnored(filepath.Join(dirPath, name), root, false) {
				continue
			}
			missing = append(missing, name)
		}
		sort.Strings(missing)
		for _, name := range missing {
			a.Stats.Missing.Add(1)
			rel := filepath.Join(dirPath, name)
			if r, err := filepath.Rel(root, rel); err == nil {
				rel = r
			}
			a.Logt(output.TagMissing, "%s — tracked but not found on disk\n", rel)
			a.JSONLog(map[string]any{
				"event":      "missing",
				"file":       rel,
				"ghost_path": gp,
			})
		}
	}
}

// cleanGhostFile removes entries for missing files from a single ghost file.
func (a *App) cleanGhostFile(ghostPath string) int64 {
	dirPath := filepath.Dir(ghostPath)
	gs := a.getGhostState(ghostPath)
	gs.mu.Lock()
	defer gs.mu.Unlock()

	data, err := ghost.ReadGhost(ghostPath)
	if err != nil {
		a.Logt(output.TagError, "Failed to read %s: %v\n", ghostPath, err)
		a.Stats.Errors.Add(1)
		return 0
	}
	removed := 0
	for filename := range data {
		if _, err := os.Lstat(filepath.Join(dirPath, filename)); os.IsNotExist(err) {
			a.Logt(output.TagMissing, "Removing entry for %s\n", filename)
			delete(data, filename)
			removed++
		}
	}
	if removed > 0 {
		if a.DryRun {
			a.Logt(output.TagDryRun, "Would clean %d missing entr(y/ies) from %s\n", removed, ghostPath)
			a.JSONLog(map[string]any{
				"event":      "dry_run",
				"operation":  "clean",
				"ghost_path": ghostPath,
				"removed":    removed,
			})
			return int64(removed)
		}
		if err := ghost.WriteGhost(data, ghostPath); err != nil {
			a.Logt(output.TagError, "Failed to write %s: %v\n", ghostPath, err)
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

	a.Logt(output.TagCleaning, "Directory: %s\n", path)
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
		a.Logt(output.TagInfo, "No .ghost files found under %s\n", path)
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
		a.Logt(output.TagCleaned, "Removed %d missing file(s)\n", totalCleaned)
	} else {
		a.Logt(output.TagOK, "No missing files found\n")
	}
	return nil
}

func (a *App) updateGhostFile(ctx context.Context, job updateWorkItem) {
	if ctx.Err() != nil {
		return
	}
	gs := a.getGhostState(job.ghostPath)
	gs.mu.Lock()
	defer gs.mu.Unlock()

	data, err := ghost.ReadGhost(job.ghostPath)
	if err != nil {
		a.Logt(output.TagError, "Failed to read '%s': %v\n", job.ghostPath, err)
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
			a.Logt(output.TagWarning, "Cannot stat '%s': %v\n", filename, err)
			continue
		}
		currentHash, err := hash.CalcHash(filePath, a.Config.Buffer)
		if err != nil {
			a.Logt(output.TagError, "Failed to hash '%s': %v\n", filename, err)
			a.Stats.Errors.Add(1)
			continue
		}
		a.Stats.Bytes.Add(st.Size())
		if currentHash != fi.Blake2b {
			a.Logt(output.TagHashMismatch, "%s -- cannot update metadata.\n", filename)
			a.Stats.Corrupted.Add(1)
			continue
		}
		data[filename] = ghost.FileData{Blake2b: fi.Blake2b, Size: st.Size(), Modified: st.ModTime()}
		updatedCount++
		a.Stats.Updated.Add(1)
	}

	if updatedCount > 0 {
		if a.DryRun {
			a.Logt(output.TagDryRun, "Would update %d metadata entr(y/ies) in %s\n", updatedCount, job.ghostPath)
			a.JSONLog(map[string]any{
				"event":      "dry_run",
				"operation":  "update",
				"ghost_path": job.ghostPath,
				"updated":    updatedCount,
			})
			return
		}
		if err := ghost.WriteGhost(data, job.ghostPath); err != nil {
			a.Logt(output.TagError, "Failed to write '%s': %v\n", job.ghostPath, err)
			a.Stats.Errors.Add(1)
			return
		}
		a.Logt(output.TagUpdated, "%d metadata update(s) in %s\n", updatedCount, job.ghostPath)
	}
}

// ListGhosts prints a formatted table of all tracked files in a .ghost file or directory.
func (a *App) ListGhosts(path string, recursive bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}

	var ghostPaths []string
	if !fi.IsDir() && filepath.Base(path) == ".ghost" {
		ghostPaths = append(ghostPaths, path)
	} else if fi.IsDir() {
		err := filepath.WalkDir(path, func(fp string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !recursive && d.IsDir() && fp != path {
				return filepath.SkipDir
			}
			if !d.IsDir() && d.Name() == ".ghost" {
				ghostPaths = append(ghostPaths, fp)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking directory: %w", err)
		}
	} else {
		return fmt.Errorf("path must be a directory or a .ghost file")
	}

	if len(ghostPaths) == 0 {
		a.Logt(output.TagHint, "No .ghost files found under %s — run 'dataGhost add -r %s' to start tracking.\n", path, path)
		return nil
	}
	sort.Strings(ghostPaths)

	// JSON mode: emit structured events instead of the formatted table.
	if a.JSONOutput {
		for _, gp := range ghostPaths {
			data, err := ghost.ReadGhost(gp)
			if err != nil {
				a.JSONLog(map[string]any{"event": "error", "ghost_path": gp, "error": err.Error()})
				continue
			}
			a.JSONLog(map[string]any{"event": "ghost_file", "path": gp, "entries": len(data)})
			names := make([]string, 0, len(data))
			for name := range data {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fd := data[name]
				ev := map[string]any{
					"event":      "tracked_file",
					"ghost_path": gp,
					"file":       name,
					"hash":       fd.Blake2b,
					"size":       fd.Size,
				}
				if !fd.Modified.IsZero() {
					ev["modified"] = fd.Modified.Format(time.RFC3339Nano)
				}
				if fd.Mode != "" {
					ev["mode"] = fd.Mode
				}
				a.JSONLog(ev)
			}
		}
		return nil
	}

	for _, gp := range ghostPaths {
		data, err := ghost.ReadGhost(gp)
		if err != nil {
			a.Logt(output.TagError, "Failed to read '%s': %v\n", gp, err)
			continue
		}
		if len(data) == 0 {
			a.Logt(output.TagInfo, "%s: (empty)\n", gp)
			continue
		}

		names := make([]string, 0, len(data))
		nameW := len("FILE")
		for name := range data {
			names = append(names, name)
			nameW = max(nameW, output.Width(name))
		}
		sort.Strings(names)
		nameW = min(nameW, 40)

		a.outputMu.Lock()
		fmt.Printf("\n%s %s\n", output.TagGhost.String(), gp)
		fmt.Printf("  %s %-64s %10s  %-19s\n",
			output.Pad("FILE", nameW), "BLAKE2B", "SIZE", "MODIFIED")
		fmt.Printf("  %s\n", strings.Repeat(output.Glyphs.BoxH, nameW+64+10+19+3))
		for _, name := range names {
			fd := data[name]
			sizeStr := output.HumanBytes(fd.Size)
			if a.RawBytes {
				sizeStr = fmt.Sprintf("%d", fd.Size)
			}
			modStr := fd.Modified.Format("2006-01-02 15:04:05")
			if fd.Modified.IsZero() {
				modStr = "-"
			}
			fmt.Printf("  %s %-64s %10s  %-19s\n",
				output.Pad(output.Truncate(name, nameW), nameW), fd.Blake2b, sizeStr, modStr)
		}
		a.outputMu.Unlock()
	}
	return nil
}

// ghostconfTemplate is written by the init command.
const ghostconfTemplate = `# dataGhost configuration
# Files and directories to skip (globs, names, or paths relative to the target):
ignore:
  - "*.tmp"
  - "*.log"
  - ".git/"

# buffer: 262144       # read buffer size in bytes (0 = auto-sized)
# parallel: 4          # worker count (default: CPU count)
# quiet: false         # print only a one-line summary
# show_progress: true  # render the progress bar
# force: false         # overwrite tracked hashes without prompting
`

// InitConfig writes a commented .ghostconf template into dir.
func (a *App) InitConfig(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("init requires a directory path")
	}
	target := filepath.Join(dir, ".ghostconf")
	if _, err := os.Lstat(target); err == nil && !a.Config.Force {
		return fmt.Errorf(".ghostconf already exists at '%s' (use -f to overwrite)", target)
	}
	if a.DryRun {
		a.Logt(output.TagDryRun, "Would create %s\n", target)
		return nil
	}
	if err := os.WriteFile(target, []byte(ghostconfTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write '%s': %w", target, err)
	}
	a.Logt(output.TagCreated, "%s — edit the ignore rules to taste\n", target)
	return nil
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

	a.Logt(output.TagUpdating, "Searching for .ghost files in: %s\n", path)
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
	a.Logt(output.TagCompleted, "Processed %d ghost file(s)\n", len(items))
	return nil
}

// PrintSummary renders the final operation summary (box, one-liner, or JSON).
func (a *App) PrintSummary(opName string, interrupted bool) {
	elapsed := time.Since(a.StartTime).Round(time.Millisecond)
	snapshot := a.Stats.Snapshot()

	if a.JSONOutput {
		summary := map[string]any{
			"event":    "summary",
			"duration": elapsed.String(),
			"stats":    snapshot,
		}
		if a.DryRun {
			summary["dry_run"] = true
		}
		if interrupted {
			summary["partial"] = true
		}
		a.outputMu.Lock()
		defer a.outputMu.Unlock()
		b, _ := json.Marshal(summary)
		fmt.Println(string(b))
		return
	}

	// Quiet mode: exactly one greppable line instead of silence.
	if a.Config.Quiet {
		parts := []string{}
		add := func(key, label string) {
			if v := snapshot[key]; v > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", v, label))
			}
		}
		add("ok", "ok")
		add("corrupted", "corrupted")
		add("missing", "missing")
		add("untracked", "untracked")
		add("mode_drift", "mode_drift")
		add("added", "added")
		add("modified", "modified")
		add("updated", "updated")
		add("deleted", "deleted")
		add("skipped", "skipped")
		add("errors", "errors")
		body := strings.Join(parts, ", ")
		if body == "" {
			body = "nothing to report"
		}
		line := fmt.Sprintf("dataghost %s: %s in %s", opName, body, elapsed)
		if a.DryRun {
			line += " [dry-run]"
		}
		if interrupted {
			line += " (partial)"
		}
		a.outputMu.Lock()
		defer a.outputMu.Unlock()
		fmt.Println(line)
		return
	}

	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.clearProgressLocked()
	fmt.Println()

	// Celebrate a fully clean check.
	if opName == "check" && snapshot["ok"] > 0 && snapshot["corrupted"] == 0 &&
		snapshot["missing"] == 0 && snapshot["errors"] == 0 {
		fmt.Printf("%s%s All %d files intact%s\n\n",
			output.ColorGreen, output.Glyphs.Check, snapshot["ok"], output.ColorReset)
	}

	w := min(max(output.TermWidth()-2, 43), 64)
	v := output.ColorBlue + output.Glyphs.BoxV + output.ColorReset
	top := output.ColorBlue + output.Glyphs.BoxTL + strings.Repeat(output.Glyphs.BoxH, w) + output.Glyphs.BoxTR + output.ColorReset
	mid := output.ColorBlue + output.Glyphs.BoxJoinL + strings.Repeat(output.Glyphs.BoxH, w) + output.Glyphs.BoxJoinR + output.ColorReset
	bot := output.ColorBlue + output.Glyphs.BoxBL + strings.Repeat(output.Glyphs.BoxH, w) + output.Glyphs.BoxBR + output.ColorReset

	fmt.Println(top)
	title := "OPERATION SUMMARY"
	lp := (w - len(title)) / 2
	fmt.Printf("%s%s%s%s%s\n", v, strings.Repeat(" ", lp), title, strings.Repeat(" ", w-len(title)-lp), v)
	fmt.Println(mid)

	line := func(label, value string, vc output.Color) {
		pad := w - len(label) - len(value) - 2
		if pad < 0 {
			pad = 0
		}
		val := value
		if code := vc.Code(); code != "" {
			val = code + value + output.ColorReset
		}
		fmt.Printf("%s %s%s%s %s\n", v, label, strings.Repeat(" ", pad), val, v)
	}
	banner := func(text string, vc output.Color) {
		pad := w - len(text) - 2
		if pad < 0 {
			pad = 0
		}
		lp, rp := pad/2, pad-pad/2
		val := text
		if code := vc.Code(); code != "" {
			val = code + text + output.ColorReset
		}
		fmt.Printf("%s %s%s%s %s\n", v, strings.Repeat(" ", lp), val, strings.Repeat(" ", rp), v)
	}

	if a.DryRun {
		fmt.Printf("%s%s%s\n", v, strings.Repeat(" ", w), v)
		banner("DRY RUN", output.CYellow)
		fmt.Printf("%s%s%s\n", v, strings.Repeat(" ", w), v)
	}
	if interrupted {
		banner("PARTIAL — INTERRUPTED", output.CYellow)
	}

	if n := snapshot["checked"]; n > 0 {
		line("Checked:", fmt.Sprintf("%d", n), output.CCyan)
	}
	if n := snapshot["ok"]; n > 0 {
		line("OK:", fmt.Sprintf("%d", n), output.CGreen)
	}
	if n := snapshot["corrupted"]; n > 0 {
		line("Corrupted:", fmt.Sprintf("%d", n), output.CRed)
	}
	if n := snapshot["missing"]; n > 0 {
		line("Missing:", fmt.Sprintf("%d", n), output.CYellow)
	}
	if n := snapshot["untracked"]; n > 0 {
		line("Untracked:", fmt.Sprintf("%d", n), output.CYellow)
	}
	if n := snapshot["mode_drift"]; n > 0 {
		line("Mode drift:", fmt.Sprintf("%d", n), output.CMagenta)
	}
	if n := snapshot["added"]; n > 0 {
		line("Added:", fmt.Sprintf("%d", n), output.CGreen)
	}
	if n := snapshot["modified"]; n > 0 {
		line("Modified:", fmt.Sprintf("%d", n), output.CBlue)
	}
	if n := snapshot["updated"]; n > 0 {
		line("Updated:", fmt.Sprintf("%d", n), output.CGreen)
	}
	if n := snapshot["deleted"]; n > 0 {
		line("Deleted:", fmt.Sprintf("%d", n), output.CRed)
	}
	if n := snapshot["skipped"]; n > 0 {
		line("Skipped:", fmt.Sprintf("%d", n), output.CYellow)
	}
	if n := snapshot["errors"]; n > 0 {
		line("Errors:", fmt.Sprintf("%d", n), output.CRed)
	}

	handled := snapshot["ok"] + snapshot["corrupted"] + snapshot["added"] +
		snapshot["modified"] + snapshot["updated"] + snapshot["deleted"]
	if handled > 0 && elapsed > 0 {
		line("Rate:", fmt.Sprintf("%.0f files/s", float64(handled)/elapsed.Seconds()), output.CNone)
	}
	if n := snapshot["bytes"]; n > 0 {
		line("Data:", fmt.Sprintf("%s at %s", output.HumanBytes(n), output.HumanRate(n, elapsed)), output.CNone)
	}
	line("Duration:", elapsed.String(), output.CNone)
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
				if cur%10 == 0 {
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
