package main

import (
	"context"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/edsrzf/mmap-go"
	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/blake2b"
)

// fileData stores metadata about tracked files.
type fileData struct {
	Blake2b  string    `yaml:"Blake2b"`
	Size     int64     `yaml:"size,omitempty"`
	Modified time.Time `yaml:"modified,omitempty"`
}

// conf represents configuration settings from a .ghostconf file.
type conf struct {
	Ignore       []string `yaml:"ignore"`
	Buffer       int      `yaml:"buffer"`
	Quiet        bool     `yaml:"quiet"`
	Parallel     int      `yaml:"parallel"`
	Force        bool     `yaml:"force"`
	ShowProgress bool     `yaml:"show_progress"`
}

// stats tracks operation statistics with thread-safe atomic operations.
type stats struct {
	checked   atomic.Int64
	corrupted atomic.Int64
	ok        atomic.Int64
	errors    atomic.Int64
	skipped   atomic.Int64
	added     atomic.Int64
	deleted   atomic.Int64
	modified  atomic.Int64
	updated   atomic.Int64
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
// When the cap is reached, the map is cleared before inserting the new entry
// (simple eviction: acceptable for a short-lived CLI process).
type boundedMap[V any] struct {
	mu  sync.Mutex
	m   map[string]V
	cap int
}

func newBoundedMap[V any](cap int) *boundedMap[V] {
	return &boundedMap[V]{m: make(map[string]V, cap), cap: cap}
}

// loadOrStore returns the existing value for key, or stores and returns newVal.
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

// load returns the value and whether it was found.
func (b *boundedMap[V]) load(key string) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[key]
	return v, ok
}

// store unconditionally stores a value.
func (b *boundedMap[V]) store(key string, val V) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.m) >= b.cap {
		b.m = make(map[string]V, b.cap)
	}
	b.m[key] = val
}

const boundedMapCap = 1024

// app holds all runtime state, eliminating package-level globals.
type app struct {
	cfg          conf
	strict       bool
	alwaysRehash bool
	startTime    time.Time
	stats        stats

	// configCache: bounded by boundedMapCap unique directories.
	configCache *boundedMap[conf]
	// ghostMutex: sync.Map for per-ghost-file serialization.
	// sync.Map is used instead of boundedMap to prevent the race where
	// eviction removes a mutex that another goroutine is still holding,
	// allowing two goroutines to obtain different mutexes for the same path.
	ghostMutex sync.Map

	outputMu sync.Mutex
}

func newApp() *app {
	cfg := defaultConfig()
	return &app{
		cfg:         cfg,
		startTime:   time.Now(),
		configCache: newBoundedMap[conf](boundedMapCap),
	}
}

// color codes for terminal output — only emitted when stdout is a TTY.
var (
	colorReset   = ""
	colorRed     = ""
	colorGreen   = ""
	colorYellow  = ""
	colorBlue    = ""
	colorMagenta = ""
	colorCyan    = ""
	colorGray    = ""
)

func initColors() {
	fi, err := os.Stdout.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		colorReset = "\033[0m"
		colorRed = "\033[31m"
		colorGreen = "\033[32m"
		colorYellow = "\033[33m"
		colorBlue = "\033[34m"
		colorMagenta = "\033[35m"
		colorCyan = "\033[36m"
		colorGray = "\033[90m"
	}
}

// isStdinInteractive returns true if stdin is a terminal device.
func isStdinInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

const (
	minBuffer          = 64 * 1024
	defaultBuffer      = 256 * 1024
	maxBuffer          = 1024 * 1024
	mmapThreshold      = 10 * 1024 * 1024
	workerQueueSize    = 1000
	progressUpdateFreq = 10
	appVersion         = "v2.3"
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, defaultBuffer)
			return &buf
		},
	}
	hashPool = sync.Pool{
		New: func() interface{} {
			h, err := blake2b.New256(nil)
			if err != nil {
				panic(fmt.Sprintf("failed to create blake2b hasher: %v", err))
			}
			return h
		},
	}
)

// ── app helpers ──────────────────────────────────────────────────────────────

// getGhostMutex returns the canonical mutex for a given ghost-file path.
// sync.Map is used so entries are never evicted while a mutex is still held.
func (a *app) getGhostMutex(ghostPath string) *sync.Mutex {
	v, _ := a.ghostMutex.LoadOrStore(ghostPath, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (a *app) logf(format string, args ...any) {
	if !a.cfg.Quiet {
		a.outputMu.Lock()
		a.clearProgress()
		fmt.Printf(format, args...)
		a.outputMu.Unlock()
	}
}

func (a *app) printProgress(current, total int64, operation string) {
	if !a.cfg.ShowProgress || a.cfg.Quiet {
		return
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	fmt.Print("\r\033[K")
	if total > 0 {
		pct := float64(current) / float64(total) * 100
		fmt.Printf("%s[%s] Processing: %d/%d (%.1f%%)%s",
			colorCyan, operation, current, total, pct, colorReset)
	} else {
		fmt.Printf("%s[%s] Processing items: %d%s",
			colorCyan, operation, current, colorReset)
	}
}

func (a *app) clearProgress() {
	if !a.cfg.ShowProgress || a.cfg.Quiet {
		return
	}
	fmt.Print("\r\033[K")
}

// ── config ───────────────────────────────────────────────────────────────────

func defaultConfig() conf {
	return conf{
		Ignore:       []string{},
		Buffer:       0,
		Quiet:        false,
		Parallel:     runtime.NumCPU(),
		Force:        false,
		ShowProgress: true,
	}
}

func loadConfigFromFile(configPath string) (conf, error) {
	cfg := defaultConfig()
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

func (a *app) loadConfig(configFile, targetPath string, useConfig, useStrict bool) error {
	a.cfg = defaultConfig()
	a.strict = useStrict
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
	a.cfg, err = loadConfigFromFile(configPath)
	return err
}

// getConfigForPath returns the effective config for a directory.
// Results are cached in the bounded configCache map.
func (a *app) getConfigForPath(dirPath string) conf {
	if a.strict {
		return a.cfg
	}
	if v, ok := a.configCache.load(dirPath); ok {
		return v
	}
	cfg := a.cfg
	if local, err := loadConfigFromFile(filepath.Join(dirPath, ".ghostconf")); err == nil {
		cfg.Ignore = local.Ignore
	}
	// loadOrStore handles the race where two goroutines compute simultaneously.
	return a.configCache.loadOrStore(dirPath, cfg)
}

// isIgnoredWithConfig checks ignore patterns using a pre-resolved config,
// avoiding a per-file cache lookup during directory walks.
func isIgnoredWithConfig(cfg conf, path, basePath string, isDir bool) bool {
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

// isIgnored is used for single-file paths only; directory walks use
// isIgnoredWithConfig directly with a locally cached config.
func (a *app) isIgnored(path, basePath string, isDir bool) bool {
	dir := filepath.Dir(path)
	if isDir {
		dir = path
	}
	return isIgnoredWithConfig(a.getConfigForPath(dir), path, basePath, isDir)
}

// ── hashing ──────────────────────────────────────────────────────────────────

func getBufferSize(fileSize int64, cfgBuffer int) int {
	if cfgBuffer > 0 {
		return cfgBuffer
	}
	switch {
	case fileSize < 1024*1024:
		return minBuffer
	case fileSize < 100*1024*1024:
		return defaultBuffer
	default:
		return maxBuffer
	}
}

func calcHashMmap(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to mmap file: %w", err)
	}
	defer func() {
		if err := data.Unmap(); err != nil {
			fmt.Fprintf(os.Stderr, "%s[WARNING]%s Failed to unmap '%s': %v\n", colorYellow, colorReset, path, err)
		}
	}()

	h, err := blake2b.New256(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create hasher: %w", err)
	}
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func calcHash(path string, cfgBuffer int) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat file '%s': %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("skipping symbolic link: '%s'", path)
	}

	fileSize := st.Size()
	if fileSize > mmapThreshold {
		if hashStr, err := calcHashMmap(path); err == nil {
			return hashStr, nil
		}
		// fall through to buffered read on mmap failure
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer f.Close()

	h := hashPool.Get().(hash.Hash)
	h.Reset()

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	bufSize := getBufferSize(fileSize, cfgBuffer)
	if cap(buf) < bufSize {
		buf = make([]byte, bufSize)
		*bufPtr = buf
	} else {
		buf = buf[:bufSize]
	}

	_, copyErr := io.CopyBuffer(h, f, buf)
	if cap(buf) <= defaultBuffer {
		bufferPool.Put(bufPtr)
	}
	if copyErr != nil {
		hashPool.Put(h)
		return "", fmt.Errorf("failed to read file '%s': %w", path, copyErr)
	}
	hashStr := fmt.Sprintf("%x", h.Sum(nil))
	hashPool.Put(h)
	return hashStr, nil
}

// ── ghost file I/O ───────────────────────────────────────────────────────────

func readGhost(ghostPath string) (map[string]fileData, error) {
	data := make(map[string]fileData)
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

func writeGhost(data map[string]fileData, ghostPath string) error {
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

func needsRehash(st os.FileInfo, stored fileData) bool {
	return st.Size() != stored.Size || !st.ModTime().Equal(stored.Modified)
}

// ── worker pool ──────────────────────────────────────────────────────────────

func runWorkers[T any](ctx context.Context, jobs []T, workerFunc func(context.Context, T), numWorkers int, operationName string, a *app) {
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
					// Drain remaining jobs so the sender can unblock.
					continue
				}
				workerFunc(ctx, job)
				cur := processed.Add(1)
				if cur%progressUpdateFreq == 0 {
					a.printProgress(cur, totalJobs, operationName)
				}
			}
		}()
	}

	for _, job := range jobs {
		select {
		case <-ctx.Done():
			// Context cancelled: stop sending. Workers will drain the channel.
			goto done
		case jobChan <- job:
		}
	}
done:
	close(jobChan)
	wg.Wait()
	a.clearProgress()
}

// ── operations ───────────────────────────────────────────────────────────────

func (a *app) addF(ctx context.Context, filePath, ghostPath, basePath string) {
	if ctx.Err() != nil {
		return
	}
	if a.isIgnored(filePath, basePath, false) {
		a.logf("%s[IGNORE]%s %s\n", colorYellow, colorReset, filePath)
		a.stats.skipped.Add(1)
		return
	}

	// Hash first: calcHash uses Lstat internally and rejects symlinks.
	currentHash, err := calcHash(filePath, a.cfg.Buffer)
	if err != nil {
		a.logf("%s[ERROR]%s Failed to hash '%s': %v\n", colorRed, colorReset, filePath, err)
		a.stats.errors.Add(1)
		return
	}

	// Stat after hashing so the recorded metadata is as recent as possible.
	// Lstat is used for consistency with calcHash — avoids silently following symlinks.
	st, err := os.Lstat(filePath)
	if err != nil {
		a.logf("%s[ERROR]%s Failed to access '%s': %v\n", colorRed, colorReset, filePath, err)
		a.stats.errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)

	// Prompt outside the lock to avoid holding it during blocking I/O.
	// Store the hash to prompt about, then re-check inside the lock before writing.
	var promptHash string
	var promptFilename string
	shouldPrompt := false
	if !a.cfg.Force {
		mu := a.getGhostMutex(ghostPath)
		mu.Lock()
		preData, preErr := readGhost(ghostPath)
		mu.Unlock()
		if preErr == nil {
			if stored, exists := preData[filename]; exists && stored.Blake2b != currentHash {
				shouldPrompt = true
				promptHash = stored.Blake2b
				promptFilename = filename
			}
		} else {
			a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, preErr)
			a.stats.errors.Add(1)
			return
		}
	}
	if shouldPrompt {
		if !isStdinInteractive() {
			a.logf("%s[WARNING]%s '%s' already tracked with a different hash. Skipping overwrite (stdin is not a terminal; use -f to force).\n", colorYellow, colorReset, promptFilename)
			return
		}
		a.outputMu.Lock()
		a.clearProgress()
		fmt.Printf("%s[WARNING]%s '%s' already tracked with a different hash.\n", colorYellow, colorReset, promptFilename)
		fmt.Printf("  Existing: %s\n  Current:  %s\n", promptHash, currentHash)
		fmt.Print("  Overwrite? (y/n): ")
		a.outputMu.Unlock()
		var resp string
		fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			a.logf("%s[CANCELLED]%s %s\n", colorYellow, colorReset, promptFilename)
			return
		}
	}

	// Full read-modify-write under lock.
	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		a.stats.errors.Add(1)
		return
	}

	if stored, exists := data[filename]; exists {
		if currentHash == stored.Blake2b {
			a.logf("%s[UNCHANGED]%s %s\n", colorGray, colorReset, filename)
			return
		}
		if shouldPrompt && stored.Blake2b != promptHash {
			a.logf("%s[WARN]%s Ghost data changed during prompt. Proceeding with update.\n", colorYellow, colorReset)
		}
		a.stats.modified.Add(1)
		a.logf("%s[UPDATED]%s %s\n", colorBlue, colorReset, filename)
	} else {
		a.stats.added.Add(1)
		a.logf("%s[ADDED]%s %s\n", colorGreen, colorReset, filename)
	}

	data[filename] = fileData{Blake2b: currentHash, Size: st.Size(), Modified: st.ModTime()}
	if err := writeGhost(data, ghostPath); err != nil {
		a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		a.stats.errors.Add(1)
	}
}

func (a *app) delF(ctx context.Context, filePath, ghostPath, _ string) {
	if ctx.Err() != nil {
		return
	}
	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		a.stats.errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)
	if _, exists := data[filename]; !exists {
		a.logf("%s[NOT FOUND]%s '%s' not in ghost database.\n", colorYellow, colorReset, filename)
		return
	}

	delete(data, filename)
	a.stats.deleted.Add(1)
	a.logf("%s[DELETED]%s %s\n", colorRed, colorReset, filename)

	if err := writeGhost(data, ghostPath); err != nil {
		a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		a.stats.errors.Add(1)
	}
}

func (a *app) checkF(ctx context.Context, filePath, ghostPath, basePath string) {
	if ctx.Err() != nil {
		return
	}
	if a.isIgnored(filePath, basePath, false) {
		a.stats.skipped.Add(1)
		return
	}

	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	data, err := readGhost(ghostPath)
	mu.Unlock()

	if err != nil {
		a.stats.errors.Add(1)
		a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		return
	}

	filename := filepath.Base(filePath)
	stored, exists := data[filename]
	if !exists {
		a.logf("%s[NOT TRACKED]%s %s\n", colorYellow, colorReset, filename)
		return
	}

	a.stats.checked.Add(1)

	st, err := os.Lstat(filePath)
	if err != nil {
		a.stats.errors.Add(1)
		a.logf("%s[ERROR]%s Failed to stat '%s': %v\n", colorRed, colorReset, filePath, err)
		return
	}

	if !a.alwaysRehash && !needsRehash(st, stored) {
		a.stats.ok.Add(1)
		a.logf("%s[OK]%s %s %s(cached)%s\n", colorGreen, colorReset, filename, colorGray, colorReset)
		return
	}

	currentHash, err := calcHash(filePath, a.cfg.Buffer)
	if err != nil {
		a.stats.errors.Add(1)
		a.logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		return
	}

	if currentHash == stored.Blake2b {
		a.stats.ok.Add(1)
		a.logf("%s[OK]%s %s\n", colorGreen, colorReset, filename)
	} else {
		a.stats.corrupted.Add(1)
		a.logf("%s[CORRUPTED]%s %s\n  Expected: %s\n  Current:  %s\n",
			colorRed, colorReset, filename, stored.Blake2b, currentHash)
	}
}

// processFiles walks path and dispatches each file to operation via a worker pool.
// The config for each directory is resolved once per directory, not per file.
func (a *app) processFiles(ctx context.Context, path string, recursive bool,
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

	a.logf("%s[PROCESSING]%s Directory: %s (recursive: %v)\n", colorCyan, colorReset, path, recursive)

	jobChan := make(chan workItem, workerQueueSize)
	var wg sync.WaitGroup
	var processed atomic.Int64

	numWorkers := a.cfg.Parallel
	if numWorkers < 1 {
		numWorkers = 1
	}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				if ctx.Err() != nil {
					continue // drain channel so walk goroutine can unblock
				}
				operation(ctx, job.filePath, job.ghostPath, job.basePath)
				cur := processed.Add(1)
				if cur%progressUpdateFreq == 0 {
					a.printProgress(cur, 0, operationName)
				}
			}
		}()
	}

	// Resolve config once per directory during the walk.
	// dirConfigCache is accessed only from the WalkDir callback, which runs on
	// a single goroutine, so no synchronisation is needed here. If the walk is
	// ever parallelised this cache must be made goroutine-safe (e.g. replaced
	// with a.configCache / sync.Map).
	dirConfigCache := make(map[string]conf)
	getDirCfg := func(dir string) conf {
		if c, ok := dirConfigCache[dir]; ok {
			return c
		}
		c := a.getConfigForPath(dir)
		dirConfigCache[dir] = c
		return c
	}

	walkErr := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			a.logf("%s[ERROR]%s Accessing '%s': %v\n", colorRed, colorReset, filePath, err)
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
			if isIgnoredWithConfig(dirCfg, filePath, path, true) {
				a.logf("%s[SKIP DIR]%s %s\n", colorYellow, colorReset, filePath)
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
		if isIgnoredWithConfig(dirCfg, filePath, path, false) {
			// Count ignored files so the summary reflects all skipped entries.
			a.stats.skipped.Add(1)
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
	a.logf("%s[COMPLETED]%s Processed %d file(s)\n", colorGreen, colorReset, processed.Load())
	return nil
}

// cleanGhostFile removes entries for missing files from a single ghost file.
// Returns the number of entries removed. Uses defer for consistent mutex release.
func (a *app) cleanGhostFile(ghostPath string) int64 {
	dirPath := filepath.Dir(ghostPath)
	mu := a.getGhostMutex(ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		a.logf("%s[ERROR]%s Failed to read %s: %v\n", colorRed, colorReset, ghostPath, err)
		a.stats.errors.Add(1)
		return 0
	}
	removed := 0
	for filename := range data {
		if _, err := os.Lstat(filepath.Join(dirPath, filename)); os.IsNotExist(err) {
			a.logf("%s[MISSING]%s Removing entry for %s\n", colorYellow, colorReset, filename)
			delete(data, filename)
			removed++
		}
	}
	if removed > 0 {
		if err := writeGhost(data, ghostPath); err != nil {
			a.logf("%s[ERROR]%s Failed to write %s: %v\n", colorRed, colorReset, ghostPath, err)
			a.stats.errors.Add(1)
			return 0
		}
	}
	return int64(removed)
}

func (a *app) clean(ctx context.Context, path string, recursive bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("clean command requires a directory path")
	}

	a.logf("%s[CLEANING]%s Directory: %s\n", colorCyan, colorReset, path)
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
		a.logf("%s[INFO]%s No .ghost files found\n", colorCyan, colorReset)
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
		a.logf("%s[CLEANED]%s Removed %d missing file(s)\n", colorGreen, colorReset, totalCleaned)
	} else {
		a.logf("%s[OK]%s No missing files found\n", colorGreen, colorReset)
	}
	return nil
}

func (a *app) updateGhostFile(ctx context.Context, job updateWorkItem) {
	if ctx.Err() != nil {
		return
	}
	mu := a.getGhostMutex(job.ghostPath)
	mu.Lock()
	defer mu.Unlock()

	data, err := readGhost(job.ghostPath)
	if err != nil {
		a.logf("%s[ERROR]%s Failed to read '%s': %v\n", colorRed, colorReset, job.ghostPath, err)
		a.stats.errors.Add(1)
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
			a.logf("%s[WARNING]%s Cannot stat '%s': %v\n", colorYellow, colorReset, filename, err)
			continue
		}
		currentHash, err := calcHash(filePath, a.cfg.Buffer)
		if err != nil {
			a.logf("%s[ERROR]%s Failed to hash '%s': %v\n", colorRed, colorReset, filename, err)
			a.stats.errors.Add(1)
			continue
		}
		if currentHash != fi.Blake2b {
			a.logf("%s[HASH MISMATCH]%s %s — cannot update metadata.\n", colorRed, colorReset, filename)
			a.stats.corrupted.Add(1)
			continue
		}
		data[filename] = fileData{Blake2b: fi.Blake2b, Size: st.Size(), Modified: st.ModTime()}
		updatedCount++
		a.stats.updated.Add(1)
	}

	if updatedCount > 0 {
		if err := writeGhost(data, job.ghostPath); err != nil {
			a.logf("%s[ERROR]%s Failed to write '%s': %v\n", colorRed, colorReset, job.ghostPath, err)
			a.stats.errors.Add(1)
			return
		}
		a.logf("%s[UPDATED]%s %d metadata update(s) in %s\n", colorGreen, colorReset, updatedCount, job.ghostPath)
	}
}

func (a *app) update(ctx context.Context, path string, recursive bool) error {
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

	a.logf("%s[UPDATING]%s Searching for .ghost files in: %s\n", colorCyan, colorReset, path)
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

	runWorkers(ctx, items, a.updateGhostFile, a.cfg.Parallel, "update", a)
	a.logf("%s[COMPLETED]%s Processed %d ghost file(s)\n", colorGreen, colorReset, len(items))
	return nil
}

// ── summary & help ───────────────────────────────────────────────────────────

func (a *app) printSummary() {
	elapsed := time.Since(a.startTime).Round(time.Millisecond)
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.clearProgress()
	fmt.Println()

	const w = 43
	top := colorBlue + "╔" + strings.Repeat("═", w) + "╗" + colorReset
	mid := colorBlue + "╠" + strings.Repeat("═", w) + "╣" + colorReset
	bot := colorBlue + "╚" + strings.Repeat("═", w) + "╝" + colorReset
	bar := colorBlue + "║" + colorReset

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
			v = vc + value + colorReset
		}
		fmt.Printf("%s %s%*s%s %s\n", bar, label, pad, "", v, bar)
	}

	if v := a.stats.checked.Load(); v > 0 {
		line("Checked:", fmt.Sprintf("%d", v), colorCyan)
	}
	if v := a.stats.ok.Load(); v > 0 {
		line("OK:", fmt.Sprintf("%d", v), colorGreen)
	}
	if v := a.stats.corrupted.Load(); v > 0 {
		line("Corrupted:", fmt.Sprintf("%d", v), colorRed)
	}
	if v := a.stats.added.Load(); v > 0 {
		line("Added:", fmt.Sprintf("%d", v), colorGreen)
	}
	if v := a.stats.modified.Load(); v > 0 {
		line("Modified:", fmt.Sprintf("%d", v), colorBlue)
	}
	if v := a.stats.updated.Load(); v > 0 {
		line("Updated:", fmt.Sprintf("%d", v), colorGreen)
	}
	if v := a.stats.deleted.Load(); v > 0 {
		line("Deleted:", fmt.Sprintf("%d", v), colorRed)
	}
	if v := a.stats.skipped.Load(); v > 0 {
		line("Skipped:", fmt.Sprintf("%d", v), colorYellow)
	}
	if v := a.stats.errors.Load(); v > 0 {
		line("Errors:", fmt.Sprintf("%d", v), colorRed)
	}
	line("Duration:", elapsed.String(), "")
	fmt.Println(bot)
}

// boxLine returns a single bordered line padded to exactly w inner characters.
func boxLine(w int, text string) string {
	pad := w - len(text)
	if pad < 0 {
		pad = 0
	}
	lp := pad / 2
	rp := pad - lp
	return colorBlue + "║" + colorReset + strings.Repeat(" ", lp) + text + strings.Repeat(" ", rp) + colorBlue + "║" + colorReset + "\n"
}

func help() {
	const w = 58 // inner width of the help box
	top := colorBlue + "╔" + strings.Repeat("═", w) + "╗" + colorReset + "\n"
	bot := colorBlue + "╚" + strings.Repeat("═", w) + "╝" + colorReset + "\n"
	fmt.Print(
		top +
			boxLine(w, "dataGhost "+appVersion) +
			boxLine(w, "File Integrity Tracking Utility") +
			bot + "\n" +
			colorYellow + "USAGE:" + colorReset + "\n" +
			"  dataGhost [OPTIONS] COMMAND " + colorGray + "[PATH]" + colorReset + "\n\n" +
			colorYellow + "COMMANDS:" + colorReset + "\n" +
			"  " + colorGreen + "add" + colorReset + "       Add files to tracking\n" +
			"  " + colorRed + "del" + colorReset + "       Remove files from tracking\n" +
			"  " + colorCyan + "check" + colorReset + "     Verify file integrity\n" +
			"  " + colorYellow + "clean" + colorReset + "     Remove missing file entries from tracking\n" +
			"  " + colorMagenta + "update" + colorReset + "    Update old .ghost files with size/modification metadata\n\n" +
			colorYellow + "OPTIONS:" + colorReset + "\n" +
			"  " + colorCyan + "-r" + colorReset + "              Process directories recursively\n" +
			"  " + colorCyan + "-p" + colorReset + " N            Set number of parallel workers (default: CPU count)\n" +
			"  " + colorCyan + "-f" + colorReset + "              Force operations without prompts\n" +
			"  " + colorCyan + "-qc" + colorReset + "             Quick check: skip rehash if size/modtime unchanged\n" +
			"  " + colorCyan + "-q" + colorReset + "              Quiet mode\n" +
			"  " + colorCyan + "-c" + colorReset + "              Load .ghostconf from target directory\n" +
			"  " + colorCyan + "-cf" + colorReset + " " + colorGray + "FILE" + colorReset + "        Load config from a specific file\n" +
			"  " + colorCyan + "-cs" + colorReset + "             Strict mode (no local overrides)\n" +
			"  " + colorCyan + "-csf" + colorReset + " " + colorGray + "FILE" + colorReset + "       Load config from file (strict mode)\n\n" +
			colorYellow + "CONFIG FILE EXAMPLE " + colorGray + "(.ghostconf)" + colorReset + ":\n" +
			"  " + colorCyan + "ignore" + colorReset + ":\n" +
			"    - " + colorGreen + "\"*.tmp\"" + colorReset + "\n" +
			"    - " + colorGreen + "\"*.log\"" + colorReset + "\n" +
			"    - " + colorGreen + "\"node_modules/\"" + colorReset + "\n" +
			"    - " + colorGreen + "\".git/\"" + colorReset + "\n" +
			"  " + colorCyan + "buffer" + colorReset + ": " + colorGreen + "262144" + colorReset + "\n" +
			"  " + colorCyan + "parallel" + colorReset + ": " + colorGreen + "4" + colorReset + "\n" +
			"  " + colorCyan + "show_progress" + colorReset + ": " + colorGreen + "true" + colorReset + "\n\n" +
			colorYellow + "EXIT CODES:" + colorReset + "\n" +
			"  0  Success\n" +
			"  1  Corruption detected / unexpected changes\n" +
			"  2  Error occurred\n",
	)
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	initColors()

	var (
		useConfig        bool
		useStrictConfig  bool
		configFile       string
		strictConfigFile string
		parallelism      int
		quietMode        bool
		recursive        bool
		forceOverwrite   bool
		quickCheck       bool
	)
	flag.BoolVar(&useConfig, "c", false, "Load .ghostconf from target directory")
	flag.BoolVar(&useStrictConfig, "cs", false, "Load .ghostconf (strict mode)")
	flag.StringVar(&configFile, "cf", "", "Load config from file")
	flag.StringVar(&strictConfigFile, "csf", "", "Load config from file (strict mode)")
	flag.IntVar(&parallelism, "p", runtime.NumCPU(), "Number of parallel workers")
	flag.BoolVar(&quietMode, "q", false, "Quiet mode")
	flag.BoolVar(&recursive, "r", false, "Process recursively")
	flag.BoolVar(&forceOverwrite, "f", false, "Force operations")
	flag.BoolVar(&quickCheck, "qc", false, "Quick check")
	flag.Parse()

	if flag.NArg() < 2 {
		help()
		os.Exit(2)
	}
	command := flag.Arg(0)
	path := flag.Arg(1)

	a := newApp()
	a.alwaysRehash = !isFlagSet("qc") // full rehash by default; -qc disables it

	useAnyConfig := useConfig || useStrictConfig || configFile != "" || strictConfigFile != ""
	isStrict := useStrictConfig || strictConfigFile != ""
	finalCF := strictConfigFile
	if finalCF == "" {
		finalCF = configFile
	}

	if err := a.loadConfig(finalCF, path, useAnyConfig, isStrict); err != nil {
		fmt.Printf("%s[FATAL]%s Failed to load config: %v\n", colorRed, colorReset, err)
		os.Exit(2)
	}

	if isFlagSet("p") {
		if parallelism < 1 {
			fmt.Printf("%s[FATAL]%s Parallelism must be >= 1, got %d\n", colorRed, colorReset, parallelism)
			os.Exit(2)
		}
		a.cfg.Parallel = parallelism
	}
	if a.cfg.Parallel < 1 {
		a.cfg.Parallel = 1
	}
	if isFlagSet("q") {
		a.cfg.Quiet = quietMode
	}
	if isFlagSet("f") {
		a.cfg.Force = forceOverwrite
	}

	// Context with SIGINT/SIGTERM cancellation for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var opErr error
	switch command {
	case "add":
		opErr = a.processFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.addF(ctx, fp, gp, bp) }, "add")
	case "del":
		opErr = a.processFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.delF(ctx, fp, gp, bp) }, "delete")
	case "check":
		if !a.alwaysRehash {
			fmt.Printf("%s[WARNING]%s Quick check mode: does NOT detect bit rot.\n", colorYellow, colorReset)
		}
		opErr = a.processFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.checkF(ctx, fp, gp, bp) }, "check")
	case "clean":
		opErr = a.clean(ctx, path, recursive)
	case "update":
		opErr = a.update(ctx, path, recursive)
	default:
		fmt.Printf("%s[ERROR]%s Unknown command: %s\n", colorRed, colorReset, command)
		help()
		os.Exit(2)
	}

	if ctx.Err() != nil {
		fmt.Printf("\n%s[INTERRUPTED]%s Operation cancelled.\n", colorYellow, colorReset)
	}

	if opErr != nil {
		fmt.Printf("%s[FATAL]%s %v\n", colorRed, colorReset, opErr)
		os.Exit(2)
	}

	if !a.cfg.Quiet {
		a.printSummary()
	}

	// Exit code logic — consistent across all commands:
	//   1 = data integrity issue (corruption detected, or unexpected hash
	//       change seen during add/check)
	//   2 = operational error (takes precedence over exit 1)
	exitCode := 0
	if a.stats.corrupted.Load() > 0 {
		exitCode = 1
	}
	// modified > 0 during add means an existing entry was overwritten with a
	// new hash — flag it so callers can detect unexpected changes.
	// Note: checkF never increments modified; corruption during check is
	// reflected solely by corrupted (already handled above).
	if a.stats.modified.Load() > 0 && command == "add" {
		exitCode = 1
	}
	// Errors always override to exit 2.
	if a.stats.errors.Load() > 0 {
		exitCode = 2
	}
	os.Exit(exitCode)
}
