package main

import (
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

// color codes for terminal output
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
)

const (
	minBuffer          = 64 * 1024        // 64 KB
	defaultBuffer      = 256 * 1024       // 256 KB
	maxBuffer          = 1024 * 1024      // 1 MB
	mmapThreshold      = 10 * 1024 * 1024 // use mmap for files > 10MB
	workerQueueSize    = 1000
	progressUpdateFreq = 10 // update progress every N items
)

var (
	globalStats  stats
	rootConfig   conf
	strictConfig bool
	forceCheck   bool
	startTime    time.Time

	// concurrency and pooling
	configCache = sync.Map{}
	ghostMutex  = sync.Map{}
	outputMutex = sync.Mutex{}
	bufferPool  = sync.Pool{
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

// getGhostMutex returns or creates a mutex for a specific ghost file path to ensure
// thread-safe writes.
func getGhostMutex(ghostPath string) *sync.Mutex {
	mutex, _ := ghostMutex.LoadOrStore(ghostPath, &sync.Mutex{})
	return mutex.(*sync.Mutex)
}

// logf prints formatted output unless in quiet mode. It is thread-safe.
func logf(format string, args ...any) {
	if !rootConfig.Quiet {
		outputMutex.Lock()
		clearProgress()
		fmt.Printf(format, args...)
		outputMutex.Unlock()
	}
}

// logln prints output unless in quiet mode. It is thread-safe.
func logln(args ...any) {
	if !rootConfig.Quiet {
		outputMutex.Lock()
		clearProgress()
		fmt.Println(args...)
		outputMutex.Unlock()
	}
}

// printProgress displays a progress bar.
func printProgress(current, total int64, operation string) {
	if !rootConfig.ShowProgress || rootConfig.Quiet {
		return
	}
	outputMutex.Lock()
	defer outputMutex.Unlock()

	if total > 0 {
		percentage := float64(current) / float64(total) * 100
		fmt.Printf("%s[%s] Processing: %d/%d (%.1f%%)%s",
			colorCyan, operation, current, total, percentage, colorReset)
	} else {
		// When total is 0, show a running count instead of a percentage.
		fmt.Printf("%s[%s] Processing items: %d",
			colorCyan, operation, current)
	}
}

// clearProgress clears the progress line from the terminal.
func clearProgress() {
	if !rootConfig.ShowProgress || rootConfig.Quiet {
		return
	}
	fmt.Print("\r\033[K")
}

// getDefaultConfig returns default configuration settings.
func getDefaultConfig() conf {
	return conf{
		Ignore:       []string{},
		Buffer:       0,
		Quiet:        false,
		Parallel:     runtime.NumCPU(),
		Force:        false,
		ShowProgress: true,
	}
}

// loadConfigFromFile loads configuration from a YAML file.
func loadConfigFromFile(configPath string) (conf, error) {
	config := getDefaultConfig()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil // No config file is not an error
	}

	yamlBytes, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("failed to read config file '%s': %w", configPath, err)
	}

	if err := yaml.Unmarshal(yamlBytes, &config); err != nil {
		return config, fmt.Errorf("failed to parse config YAML from '%s': %w", configPath, err)
	}
	return config, nil
}

// loadConfig loads the root configuration from a file if specified.
func loadConfig(configFile, targetPath string, useConfig, useStrict bool) error {
	rootConfig = getDefaultConfig()
	strictConfig = useStrict

	if !useConfig {
		return nil
	}

	configPath := configFile
	if configPath == "" {
		// Auto-detect .ghostconf in the target path
		absTargetPath, err := filepath.Abs(targetPath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for '%s': %w", targetPath, err)
		}
		stat, err := os.Stat(absTargetPath)
		if err != nil {
			return fmt.Errorf("failed to stat target path '%s': %w", absTargetPath, err)
		}
		rootDir := absTargetPath
		if !stat.IsDir() {
			rootDir = filepath.Dir(absTargetPath)
		}
		configPath = filepath.Join(rootDir, ".ghostconf")
	}

	var err error
	rootConfig, err = loadConfigFromFile(configPath)
	return err
}

// getConfigForPath retrieves configuration for a specific directory path,
// allowing for local .ghostconf overrides unless in strict mode.
func getConfigForPath(dirPath string) conf {
	if strictConfig {
		return rootConfig
	}
	if cached, ok := configCache.Load(dirPath); ok {
		return cached.(conf)
	}

	config := rootConfig
	localConfigPath := filepath.Join(dirPath, ".ghostconf")
	if localConfig, err := loadConfigFromFile(localConfigPath); err == nil {
		config.Ignore = localConfig.Ignore
	}

	actual, _ := configCache.LoadOrStore(dirPath, config)
	return actual.(conf)
}

// isIgnored checks if a file or directory should be ignored based on ignore patterns.
func isIgnored(path, basePath string, isDir bool) bool {
	dir := filepath.Dir(path)
	if isDir {
		dir = path
	}
	config := getConfigForPath(dir)
	if len(config.Ignore) == 0 {
		return false
	}

	relPath, err := filepath.Rel(basePath, path)
	if err != nil {
		relPath = filepath.Base(path)
	}
	relPath = filepath.ToSlash(relPath)
	baseName := filepath.Base(path)

	for _, pattern := range config.Ignore {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		pattern = filepath.ToSlash(pattern)

		isDirPattern := strings.HasSuffix(pattern, "/")
		if isDirPattern {
			pattern = strings.TrimSuffix(pattern, "/")
		}

		// directory pattern can't match a file.
		if isDirPattern && !isDir {
			continue
		}

		// match against the basename (e.g., "*.log") or the full relative path ("build/output.txt").
		matchName, _ := filepath.Match(pattern, baseName)
		matchPath, _ := filepath.Match(pattern, relPath)

		if matchName || matchPath {
			return true
		}

		// handle directory matches like "node_modules/" matching "path/to/node_modules/file.js"
		if isDirPattern && strings.HasPrefix(relPath, pattern+"/") {
			return true
		}
	}
	return false
}

// getBufferSize determines optimal buffer size for file reading.
func getBufferSize(fileSize int64) int {
	if rootConfig.Buffer > 0 {
		return rootConfig.Buffer
	}
	switch {
	case fileSize < 1024*1024: // < 1MB
		return minBuffer
	case fileSize < 100*1024*1024: // < 100MB
		return defaultBuffer
	default:
		return maxBuffer
	}
}

// calcHashMmap calculates hash using memory mapping for large files.
func calcHashMmap(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to mmap file: %w", err)
	}
	defer func() {
		if err := data.Unmap(); err != nil {
			logf("%s[WARNING]%s Failed to unmap file '%s': %v\n", colorYellow, colorReset, path, err)
		}
	}()

	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// calcHash computes the BLAKE2b hash of a file. It uses memory-mapping for large files.
func calcHash(path string) (string, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat file '%s': %w", path, err)
	}
	if stat.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("skipping symbolic link: '%s'", path)
	}

	fileSize := stat.Size()
	if fileSize > mmapThreshold {
		hashStr, err := calcHashMmap(path)
		if err == nil {
			return hashStr, nil
		}
		// fall back to regular reading if mmap fails
		logf("%s[INFO]%s mmap failed for '%s', falling back to buffered read: %v\n", colorCyan, colorReset, path, err)
	}

	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer file.Close()

	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buffer := *bufPtr
	bufSize := getBufferSize(fileSize)
	if cap(buffer) < bufSize {
		// Pooled buffer is too small, a new one will be allocated for this operation.
		buffer = make([]byte, bufSize)
	} else {
		// Reuse pooled buffer by slicing it to the required size.
		buffer = buffer[:bufSize]
	}

	if _, err := io.CopyBuffer(h, file, buffer); err != nil {
		return "", fmt.Errorf("failed to read file '%s': %w", path, err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// readGhost reads the ghost file and returns tracked file data.
func readGhost(ghostPath string) (map[string]fileData, error) {
	data := make(map[string]fileData)
	yamlBytes, err := os.ReadFile(ghostPath)
	if os.IsNotExist(err) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read ghost file '%s': %w", ghostPath, err)
	}
	if len(yamlBytes) == 0 {
		return data, nil
	}
	if err := yaml.Unmarshal(yamlBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to parse YAML from '%s': %w", ghostPath, err)
	}
	return data, nil
}

// writeGhost writes tracked file data to the ghost file atomically.
func writeGhost(data map[string]fileData, ghostPath string) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// write to a temporary file
	tmpPath := ghostPath + ".tmp"
	if err := os.WriteFile(tmpPath, yamlBytes, 0644); err != nil {
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Rename temporary file to the actual ghost file
	if err := os.Rename(tmpPath, ghostPath); err != nil {
		os.Remove(tmpPath) // Clean up on error
		return fmt.Errorf("failed to finalize ghost file: %w", err)
	}
	return nil
}

// needsRehash checks if a file needs rehashing based on modification time and size.
func needsRehash(stat os.FileInfo, stored fileData) bool {
	return stat.Size() != stored.Size || !stat.ModTime().Equal(stored.Modified)
}

// runWorkers starts a pool of goroutines to process a channel of jobs.
func runWorkers[T any](jobs []T, workerFunc func(T), numWorkers int, operationName string) {
	if len(jobs) == 0 {
		logf("%s[INFO]%s No items to process\n", colorCyan, colorReset)
		return
	}

	jobChan := make(chan T, workerQueueSize)
	var wg sync.WaitGroup
	var processed atomic.Int64
	totalJobs := int64(len(jobs))

	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				workerFunc(job)
				current := processed.Add(1)
				if current%progressUpdateFreq == 0 {
					printProgress(current, totalJobs, operationName)
				}
			}
		}()
	}

	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	wg.Wait()
	clearProgress()
}

// addF adds or updates a file in the ghost database.
func addF(filePath, ghostPath, basePath string) {
	if isIgnored(filePath, basePath, false) {
		logf("%s[IGNORE]%s %s\n", colorYellow, colorReset, filePath)
		globalStats.skipped.Add(1)
		return
	}

	stat, err := os.Stat(filePath)
	if err != nil {
		logf("%s[ERROR]%s Failed to access file '%s': %v\n", colorRed, colorReset, filePath, err)
		globalStats.errors.Add(1)
		return
	}

	currentHash, err := calcHash(filePath)
	if err != nil {
		logf("%s[ERROR]%s Failed to calculate hash for '%s': %v\n", colorRed, colorReset, filePath, err)
		globalStats.errors.Add(1)
		return
	}

	mutex := getGhostMutex(ghostPath)
	mutex.Lock()

	data, err := readGhost(ghostPath)
	if err != nil {
		mutex.Unlock()
		logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		globalStats.errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)
	storedData, exists := data[filename]
	if exists {
		if currentHash == storedData.Blake2b {
			mutex.Unlock()
			logf("%s[UNCHANGED]%s %s\n", colorGray, colorReset, filename)
			return
		}

		if !rootConfig.Force {
			mutex.Unlock()
			outputMutex.Lock()
			clearProgress()
			fmt.Printf("%s[WARNING]%s File '%s' already tracked with a different hash.\n", colorYellow, colorReset, filename)
			fmt.Printf("  Existing: %s\n", storedData.Blake2b)
			fmt.Printf("  Current:  %s\n", currentHash)
			fmt.Print("  Overwrite? (y/n): ")
			var response string
			fmt.Scanln(&response)
			outputMutex.Unlock()
			if response != "y" && response != "Y" {
				logf("%s[CANCELLED]%s Operation cancelled by user for %s.\n", colorYellow, colorReset, filename)
				return
			}
			mutex.Lock()
		}
		globalStats.modified.Add(1)
		logf("%s[UPDATED]%s %s\n", colorBlue, colorReset, filename)
	} else {
		globalStats.added.Add(1)
		logf("%s[ADDED]%s %s\n", colorGreen, colorReset, filename)
	}

	data[filename] = fileData{
		Blake2b:  currentHash,
		Size:     stat.Size(),
		Modified: stat.ModTime(),
	}

	if err := writeGhost(data, ghostPath); err != nil {
		mutex.Unlock()
		logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		globalStats.errors.Add(1)
		return
	}
	mutex.Unlock()
}

// delF removes a file from the ghost database.
func delF(filePath, ghostPath, _ string) {
	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	defer mutex.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		globalStats.errors.Add(1)
		return
	}

	filename := filepath.Base(filePath)
	if _, exists := data[filename]; !exists {
		logf("%s[NOT FOUND]%s File '%s' not found in ghost database.\n", colorYellow, colorReset, filename)
		return
	}

	delete(data, filename)
	globalStats.deleted.Add(1)
	logf("%s[DELETED]%s %s\n", colorRed, colorReset, filename)

	if err := writeGhost(data, ghostPath); err != nil {
		logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		globalStats.errors.Add(1)
	}
}

// checkF verifies a file's integrity against the ghost database.
func checkF(filePath, ghostPath, basePath string) {
	if isIgnored(filePath, basePath, false) {
		globalStats.skipped.Add(1)
		return
	}

	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	data, err := readGhost(ghostPath)
	mutex.Unlock()

	if err != nil {
		globalStats.errors.Add(1)
		logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		return
	}

	filename := filepath.Base(filePath)
	storedData, exists := data[filename]
	if !exists {
		logf("%s[NOT TRACKED]%s %s\n", colorYellow, colorReset, filename)
		return
	}

	globalStats.checked.Add(1)

	stat, err := os.Stat(filePath)
	if err != nil {
		globalStats.errors.Add(1)
		logf("%s[ERROR]%s Failed to stat file '%s': %v\n", colorRed, colorReset, filePath, err)
		return
	}

	if !forceCheck && !needsRehash(stat, storedData) {
		globalStats.ok.Add(1)
		logf("%s[OK]%s %s %s(cached)%s\n", colorGreen, colorReset, filename, colorGray, colorReset)
		return
	}

	currentHash, err := calcHash(filePath)
	if err != nil {
		globalStats.errors.Add(1)
		logf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
		return
	}

	if currentHash == storedData.Blake2b {
		globalStats.ok.Add(1)
		logf("%s[OK]%s %s\n", colorGreen, colorReset, filename)
	} else {
		globalStats.corrupted.Add(1)
		logf("%s[CORRUPTED]%s %s\n", colorRed, colorReset, filename)
		logf("  Expected: %s\n", storedData.Blake2b)
		logf("  Current:  %s\n", currentHash)
	}
}

// processFiles gathers files for an operation and runs them through a worker pool.
func processFiles(path string, recursive bool, operation func(string, string, string), operationName string) error {
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path is a symbolic link, skipping: '%s'", path)
	}

	// handle a single file directly.
	if !fileInfo.IsDir() {
		dirPath := filepath.Dir(path)
		ghostPath := filepath.Join(dirPath, ".ghost")
		operation(path, ghostPath, dirPath)
		return nil
	}

	logf("%s[PROCESSING]%s Directory: %s (recursive: %v)\n", colorCyan, colorReset, path, recursive)

	jobChan := make(chan workItem, workerQueueSize)
	var wg sync.WaitGroup
	var processed atomic.Int64

	numWorkers := rootConfig.Parallel
	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				operation(job.filePath, job.ghostPath, job.basePath)
				current := processed.Add(1)
				// With a streaming pipeline, we don't know the total number of files,
				// so we show a running count instead of a percentage.
				if current%progressUpdateFreq == 0 {
					printProgress(current, 0, operationName)
				}
			}
		}()
	}

	walkErr := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			logf("%s[ERROR]%s Accessing '%s': %v\n", colorRed, colorReset, filePath, err)
			return nil // Continue walking
		}
		isDir := d.IsDir()
		if !recursive && isDir && filePath != path {
			return filepath.SkipDir
		}
		if isDir && filePath != path && isIgnored(filePath, path, true) {
			logf("%s[SKIP DIR]%s %s\n", colorYellow, colorReset, filePath)
			return filepath.SkipDir
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
		if isIgnored(filePath, path, false) {
			return nil
		}

		dirPath := filepath.Dir(filePath)
		localGhostPath := filepath.Join(dirPath, ".ghost")
		if !recursive {
			localGhostPath = filepath.Join(path, ".ghost")
		}
		jobChan <- workItem{filePath, localGhostPath, path}
		return nil
	})

	close(jobChan)
	wg.Wait()
	clearProgress()

	if walkErr != nil {
		return fmt.Errorf("error processing directory: %w", walkErr)
	}

	logf("%s[COMPLETED]%s Processed %d potential files\n", colorGreen, colorReset, processed.Load())
	return nil
}

// clean removes entries for deleted files from ghost databases.
func clean(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}
	if !fileInfo.IsDir() {
		return fmt.Errorf("clean command requires a directory path")
	}

	logf("%s[CLEANING]%s Directory: %s\n", colorCyan, colorReset, path)
	var ghostFiles []string

	if err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !recursive && d.IsDir() && filePath != path {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == ".ghost" {
			ghostFiles = append(ghostFiles, filePath)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	if len(ghostFiles) == 0 {
		logf("%s[INFO]%s No .ghost files found\n", colorCyan, colorReset)
		return nil
	}

	var totalCleaned int64
	for _, ghostPath := range ghostFiles {
		dirPath := filepath.Dir(ghostPath)
		mutex := getGhostMutex(ghostPath)
		mutex.Lock()
		data, err := readGhost(ghostPath)
		if err != nil {
			mutex.Unlock()
			logf("%s[ERROR]%s Failed to read %s: %v\n", colorRed, colorReset, ghostPath, err)
			continue
		}

		removedCount := 0
		for filename := range data {
			filePath := filepath.Join(dirPath, filename)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				logf("%s[MISSING]%s Removing entry for %s\n", colorYellow, colorReset, filename)
				delete(data, filename)
				removedCount++
			}
		}

		if removedCount > 0 {
			if err := writeGhost(data, ghostPath); err != nil {
				logf("%s[ERROR]%s Failed to write %s: %v\n", colorRed, colorReset, ghostPath, err)
			}
			atomic.AddInt64(&totalCleaned, int64(removedCount))
		}
		mutex.Unlock()
	}

	if totalCleaned > 0 {
		logf("%s[CLEANED]%s Removed %d missing file(s) from ghost databases\n", colorGreen, colorReset, totalCleaned)
	} else {
		logf("%s[OK]%s No missing files found to clean\n", colorGreen, colorReset)
	}
	return nil
}

// updateGhostFile updates a single .ghost file to include size and modified metadata.
func updateGhostFile(job updateWorkItem) {
	mutex := getGhostMutex(job.ghostPath)
	mutex.Lock()
	defer mutex.Unlock()

	data, err := readGhost(job.ghostPath)
	if err != nil {
		logf("%s[ERROR]%s Failed to read ghost file '%s': %v\n", colorRed, colorReset, job.ghostPath, err)
		globalStats.errors.Add(1)
		return
	}

	updatedCount := 0
	for filename, fileInfo := range data {
		// Skip if metadata is already present.
		if fileInfo.Size != 0 || !fileInfo.Modified.IsZero() {
			continue
		}

		filePath := filepath.Join(job.dirPath, filename)
		stat, err := os.Stat(filePath)
		if err != nil {
			logf("%s[WARNING]%s Cannot stat file '%s', skipping update: %v\n", colorYellow, colorReset, filename, err)
			continue
		}

		// Re-hash to ensure integrity before adding new metadata.
		currentHash, err := calcHash(filePath)
		if err != nil {
			logf("%s[ERROR]%s Failed to hash '%s' during update: %v\n", colorRed, colorReset, filename, err)
			globalStats.errors.Add(1)
			continue
		}

		if currentHash != fileInfo.Blake2b {
			logf("%s[HASH MISMATCH]%s %s, cannot update metadata.\n", colorRed, colorReset, filename)
			globalStats.corrupted.Add(1)
			continue
		}

		data[filename] = fileData{
			Blake2b:  fileInfo.Blake2b,
			Size:     stat.Size(),
			Modified: stat.ModTime(),
		}
		updatedCount++
		globalStats.updated.Add(1)
	}

	if updatedCount > 0 {
		if err := writeGhost(data, job.ghostPath); err != nil {
			logf("%s[ERROR]%s Failed to write updated ghost file '%s': %v\n", colorRed, colorReset, job.ghostPath, err)
			globalStats.errors.Add(1)
			return
		}
		logf("%s[UPDATED]%s Wrote %d metadata updates to %s\n", colorGreen, colorReset, updatedCount, job.ghostPath)
	}
}

// update finds and upgrades old .ghost files to include new metadata.
func update(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}

	if !fileInfo.IsDir() && filepath.Base(path) == ".ghost" {
		dirPath := filepath.Dir(path)
		updateGhostFile(updateWorkItem{ghostPath: path, dirPath: dirPath})
		return nil
	}
	if !fileInfo.IsDir() {
		return fmt.Errorf("path must be a directory or a .ghost file")
	}

	logf("%s[UPDATING]%s Searching for .ghost files in: %s\n", colorCyan, colorReset, path)
	var updateItems []updateWorkItem

	if err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !recursive && d.IsDir() && filePath != path {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == ".ghost" {
			updateItems = append(updateItems, updateWorkItem{
				ghostPath: filePath,
				dirPath:   filepath.Dir(filePath),
			})
		}
		return nil
	}); err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	runWorkers(updateItems, updateGhostFile, rootConfig.Parallel, "update")
	logf("%s[COMPLETED]%s Processed %d ghost file(s)\n", colorGreen, colorReset, len(updateItems))
	return nil
}

// printSummary displays final operation statistics.
func printSummary() {
	elapsed := time.Since(startTime).Round(time.Millisecond)

	outputMutex.Lock()
	defer outputMutex.Unlock()

	clearProgress()
	fmt.Println()

	const innerWidth = 43

	topBorder := colorBlue + "╔" + strings.Repeat("═", innerWidth) + "╗" + colorReset
	midBorder := colorBlue + "╠" + strings.Repeat("═", innerWidth) + "╣" + colorReset
	botBorder := colorBlue + "╚" + strings.Repeat("═", innerWidth) + "╝" + colorReset
	border := colorBlue + "║" + colorReset

	fmt.Println(topBorder)
	title := "OPERATION SUMMARY"
	titlePaddingLeft := (innerWidth - len(title)) / 2
	titlePaddingRight := innerWidth - len(title) - titlePaddingLeft
	fmt.Printf("%s%s%s%s%s\n", border, strings.Repeat(" ", titlePaddingLeft), title, strings.Repeat(" ", titlePaddingRight), border)
	fmt.Println(midBorder)

	printDataLine := func(label, value, valueColor string) {
		visibleLen := len(value)
		paddingSize := innerWidth - len(label) - visibleLen - 2
		if paddingSize < 0 {
			paddingSize = 0
		}

		if valueColor != "" {
			value = valueColor + value + colorReset
		}

		fmt.Printf("%s %s%*s%s %s\n", border, label, paddingSize, "", value, border)
	}

	if val := globalStats.checked.Load(); val > 0 {
		printDataLine("Checked:", fmt.Sprintf("%d", val), colorCyan)
	}
	if val := globalStats.ok.Load(); val > 0 {
		printDataLine("OK:", fmt.Sprintf("%d", val), colorGreen)
	}
	if val := globalStats.corrupted.Load(); val > 0 {
		printDataLine("Corrupted:", fmt.Sprintf("%d", val), colorRed)
	}
	if val := globalStats.added.Load(); val > 0 {
		printDataLine("Added:", fmt.Sprintf("%d", val), colorGreen)
	}
	if val := globalStats.modified.Load(); val > 0 {
		printDataLine("Modified:", fmt.Sprintf("%d", val), colorBlue)
	}
	if val := globalStats.updated.Load(); val > 0 {
		printDataLine("Updated:", fmt.Sprintf("%d", val), colorGreen)
	}
	if val := globalStats.deleted.Load(); val > 0 {
		printDataLine("Deleted:", fmt.Sprintf("%d", val), colorRed)
	}
	if val := globalStats.skipped.Load(); val > 0 {
		printDataLine("Skipped:", fmt.Sprintf("%d", val), colorYellow)
	}
	if val := globalStats.errors.Load(); val > 0 {
		printDataLine("Errors:", fmt.Sprintf("%d", val), colorRed)
	}

	printDataLine("Duration:", elapsed.String(), "")

	fmt.Println(botBorder)
}

// help displays usage information.
func help() {
	fmt.Print(
		colorBlue + "╔══════════════════════════════════════════════════════════╗" + colorReset + "\n" +
			colorBlue + "║                    dataGhost v2.1                        ║" + colorReset + "\n" +
			colorBlue + "║            File Integrity Tracking Utility               ║" + colorReset + "\n" +
			colorBlue + "╚══════════════════════════════════════════════════════════╝" + colorReset + "\n\n" +

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
			"  " + colorCyan + "-f" + colorReset + "              Force operations without prompts (e.g., overwrite)\n" +
			"  " + colorCyan + "-fc" + colorReset + "             Force hash re-calculation (ignores cached size/modtime check)\n" +
			"  " + colorCyan + "-q" + colorReset + "              Quiet mode (minimal output)\n" +
			"  " + colorCyan + "-c" + colorReset + "              Load .ghostconf from target directory\n" +
			"  " + colorCyan + "-cf" + colorReset + " " + colorGray + "FILE" + colorReset + "        Load config from a specific file\n" +
			"  " + colorCyan + "-cs" + colorReset + "             Load .ghostconf from target (strict mode: no local overrides)\n" +
			"  " + colorCyan + "-csf" + colorReset + " " + colorGray + "FILE" + colorReset + "       Load config from file (strict mode)\n\n" +

			colorYellow + "CONFIG FILE EXAMPLE (.ghostconf):" + colorReset + "\n" +
			"  ignore:\n" +
			"    - \"*.tmp\"\n" +
			"    - \"*.log\"\n" +
			"    - \"node_modules/\"\n" +
			"    - \".git/\"\n" +
			"  buffer: 262144\n" +
			"  parallel: 4\n" +
			"  show_progress: true\n\n" +

			colorYellow + "EXIT CODES:" + colorReset + "\n" +
			"  0  Success\n" +
			"  1  Corruption detected\n" +
			"  2  Error occurred\n",
	)
}

// isFlagSet checks if a flag was explicitly set by the user on the command line.
func isFlagSet(name string) bool {
	wasSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

func main() {
	startTime = time.Now()

	// flag definition
	var (
		useConfig        bool
		useStrictConfig  bool
		configFile       string
		strictConfigFile string
		parallelism      int
		quietMode        bool
		recursive        bool
		forceOverwrite   bool
	)
	flag.BoolVar(&useConfig, "c", false, "Load .ghostconf from target directory")
	flag.BoolVar(&useStrictConfig, "cs", false, "Load .ghostconf (strict mode)")
	flag.StringVar(&configFile, "cf", "", "Load config from file")
	flag.StringVar(&strictConfigFile, "csf", "", "Load config from file (strict mode)")
	flag.IntVar(&parallelism, "p", runtime.NumCPU(), "Number of parallel workers")
	flag.BoolVar(&quietMode, "q", false, "Quiet mode")
	flag.BoolVar(&recursive, "r", false, "Process recursively")
	flag.BoolVar(&forceOverwrite, "f", false, "Force operations")
	flag.BoolVar(&forceCheck, "fc", false, "Force hash calculation (ignore cache)")
	flag.Parse()

	if flag.NArg() < 2 {
		help()
		os.Exit(2)
	}
	command := flag.Arg(0)
	path := flag.Arg(1)

	// config load
	useAnyConfig := useConfig || useStrictConfig || configFile != "" || strictConfigFile != ""
	isStrict := useStrictConfig || strictConfigFile != ""
	finalConfigFile := ""
	if strictConfigFile != "" {
		finalConfigFile = strictConfigFile
	} else if configFile != "" {
		finalConfigFile = configFile
	}

	if err := loadConfig(finalConfigFile, path, useAnyConfig, isStrict); err != nil {
		fmt.Printf("%s[FATAL]%s Failed to load config: %v\n", colorRed, colorReset, err)
		os.Exit(2)
	}

	// cli overrides
	if isFlagSet("p") {
		if parallelism < 1 {
			fmt.Printf("%s[FATAL]%s Parallelism must be at least 1, got %d\n", colorRed, colorReset, parallelism)
			os.Exit(2)
		}
		rootConfig.Parallel = parallelism
	}
	if rootConfig.Parallel < 1 {
		rootConfig.Parallel = 1
	}
	if isFlagSet("q") {
		rootConfig.Quiet = quietMode
	}
	if isFlagSet("f") {
		rootConfig.Force = forceOverwrite
	}

	var err error
	switch command {
	case "add":
		err = processFiles(path, recursive, func(filePath, ghostPath, basePath string) {
			addF(filePath, ghostPath, basePath)
		}, "add")
	case "del":
		err = processFiles(path, recursive, delF, "delete")
	case "check":
		err = processFiles(path, recursive, checkF, "check")
	case "clean":
		err = clean(path, recursive)
	case "update":
		err = update(path, recursive)
	default:
		fmt.Printf("%s[ERROR]%s Unknown command: %s\n", colorRed, colorReset, command)
		help()
		os.Exit(2)
	}

	if err != nil {
		fmt.Printf("%s[FATAL]%s %v\n", colorRed, colorReset, err)
		os.Exit(2)
	}

	// summary and exit
	showSummary := !rootConfig.Quiet
	exitCode := 0

	if command == "check" || command == "update" {
		if showSummary {
			printSummary()
		}
		if globalStats.corrupted.Load() > 0 {
			exitCode = 1
		}
	} else if showSummary {
		printSummary()
	}

	if globalStats.errors.Load() > 0 {
		exitCode = 2
	}
	os.Exit(exitCode)
}
