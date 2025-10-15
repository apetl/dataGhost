package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/blake2b"
)

// fileData stores metadata about tracked files
type fileData struct {
	Blake2b  string    `yaml:"Blake2b"`
	Size     int64     `yaml:"size,omitempty"`
	Modified time.Time `yaml:"modified,omitempty"`
}

// conf represents configuration settings
type conf struct {
	Ignore       []string `yaml:"ignore"`
	Buffer       int      `yaml:"buffer"`
	Quiet        bool     `yaml:"quiet"`
	Parallel     int      `yaml:"parallel"`
	Recursive    bool     `yaml:"recursive"`
	Force        bool     `yaml:"force"`
	ShowProgress bool     `yaml:"show_progress"`
}

// stats tracks operation statistics
type stats struct {
	checked   int64
	corrupted int64
	ok        int64
	errors    int64
	skipped   int64
	added     int64
	deleted   int64
	modified  int64
	updated   int64
}

// Color codes for terminal output
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

var (
	quietMode    bool
	showProgress bool
	forceCheck   bool
	globalStats  stats
	parallelism  int
	rootConfig   conf
	strictConfig bool
	configCache  = make(map[string]conf)
	cacheMutex   sync.RWMutex
	ghostMutex   = make(map[string]*sync.Mutex)
	mutexLock    sync.Mutex
	startTime    time.Time
)

// getGhostMutex returns or creates a mutex for a specific ghost file
func getGhostMutex(ghostPath string) *sync.Mutex {
	mutexLock.Lock()
	defer mutexLock.Unlock()

	if _, exists := ghostMutex[ghostPath]; !exists {
		ghostMutex[ghostPath] = &sync.Mutex{}
	}
	return ghostMutex[ghostPath]
}

// printf prints formatted output unless in quiet mode
func printf(format string, args ...any) {
	if !quietMode {
		fmt.Printf(format, args...)
	}
}

// println prints output unless in quiet mode
func println(args ...any) {
	if !quietMode {
		fmt.Println(args...)
	}
}

// printProgress displays a progress indicator
func printProgress(current, total int64, operation string) {
	if !showProgress || quietMode {
		return
	}
	percentage := float64(current) / float64(total) * 100
	fmt.Printf("\r%s[%s] Processing: %d/%d (%.1f%%)%s",
		colorCyan, operation, current, total, percentage, colorReset)
}

// clearProgress clears the progress line
func clearProgress() {
	if !showProgress || quietMode {
		return
	}
	fmt.Print("\r\033[K")
}

// getDefaultConfig returns default configuration settings
func getDefaultConfig() conf {
	return conf{
		Ignore:       []string{},
		Buffer:       0,
		Quiet:        false,
		Parallel:     1,
		Recursive:    false,
		Force:        false,
		ShowProgress: true,
	}
}

// loadConfigFromFile loads configuration from a YAML file
func loadConfigFromFile(configPath string) (conf, error) {
	config := getDefaultConfig()

	if configPath == "" {
		return config, nil
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil
	}

	yamlBytes, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("failed to read config file '%s': %w", configPath, err)
	}

	err = yaml.Unmarshal(yamlBytes, &config)
	if err != nil {
		return config, fmt.Errorf("failed to parse config YAML from '%s': %w", configPath, err)
	}

	return config, nil
}

// loadConfig loads the root configuration
func loadConfig(configFile string, targetPath string, useConfig bool, useStrictConfig bool) error {
	rootConfig = getDefaultConfig()

	if useConfig || useStrictConfig {
		var configPath string

		if configFile != "" {
			configPath = configFile
		} else {
			absTargetPath, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for '%s': %w", targetPath, err)
			}

			var rootDir string
			if stat, err := os.Stat(absTargetPath); err == nil && stat.IsDir() {
				rootDir = absTargetPath
			} else {
				rootDir = filepath.Dir(absTargetPath)
			}

			configPath = filepath.Join(rootDir, ".ghostconf")
		}

		var err error
		rootConfig, err = loadConfigFromFile(configPath)
		if err != nil {
			return err
		}
	}

	return nil
}

// getConfigForPath retrieves configuration for a specific directory path
func getConfigForPath(dirPath string) conf {
	if strictConfig {
		return rootConfig
	}

	cacheMutex.RLock()
	if cached, exists := configCache[dirPath]; exists {
		cacheMutex.RUnlock()
		return cached
	}
	cacheMutex.RUnlock()

	config := rootConfig
	localConfigPath := filepath.Join(dirPath, ".ghostconf")

	if localConfig, err := loadConfigFromFile(localConfigPath); err == nil {
		config.Ignore = localConfig.Ignore
	}

	cacheMutex.Lock()
	configCache[dirPath] = config
	cacheMutex.Unlock()

	return config
}

// shouldIgnore checks if a file should be ignored based on patterns
func shouldIgnore(filePath string, basePath string) bool {
	config := getConfigForPath(basePath)

	if len(config.Ignore) == 0 {
		return false
	}

	relPath, err := filepath.Rel(basePath, filePath)
	if err != nil {
		relPath = filepath.Base(filePath)
	}

	relPath = filepath.ToSlash(relPath)
	fileName := filepath.Base(filePath)

	for _, pattern := range config.Ignore {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}

		pattern = filepath.ToSlash(pattern)

		if matchesPattern(relPath, pattern) || matchesPattern(fileName, pattern) {
			return true
		}
	}

	return false
}

// matchesPattern checks if a path matches a given pattern
func matchesPattern(path, pattern string) bool {
	if path == pattern {
		return true
	}

	if strings.HasSuffix(pattern, "/") {
		dirPattern := strings.TrimSuffix(pattern, "/")
		if strings.HasPrefix(path, dirPattern+"/") || path == dirPattern {
			return true
		}
	}

	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return true
		}
		pathParts := strings.Split(path, "/")
		for i := range pathParts {
			partialPath := strings.Join(pathParts[:i+1], "/")
			if matched, _ := filepath.Match(pattern, partialPath); matched {
				return true
			}
		}
	}

	if strings.Contains(path, pattern) {
		return true
	}

	return false
}

// getBufferSize determines optimal buffer size for file reading
func getBufferSize(file *os.File) int {
	if rootConfig.Buffer > 0 {
		return rootConfig.Buffer
	}

	const (
		minBuffer     = 64 * 1024
		maxBuffer     = 1024 * 1024
		defaultBuffer = 256 * 1024
	)

	stat, err := file.Stat()
	if err != nil {
		return defaultBuffer
	}

	fileSize := stat.Size()

	switch {
	case fileSize < 1024*1024:
		return minBuffer
	case fileSize < 100*1024*1024:
		return defaultBuffer
	default:
		return maxBuffer
	}
}

// calcHash computes the BLAKE2b hash of a file
func calcHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			return "", fmt.Errorf("permission denied: ensure you have read access to '%s'", path)
		}
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer file.Close()

	hash, err := blake2b.New256(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create BLAKE2b hash: %w", err)
	}

	buffer := make([]byte, getBufferSize(file))

	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err != io.EOF {
				return "", fmt.Errorf("failed to read file '%s': %w", path, err)
			}
			break
		}
		_, err = hash.Write(buffer[:bytesRead])
		if err != nil {
			return "", fmt.Errorf("failed to write to hash: %w", err)
		}
	}
	hashSum := hash.Sum(nil)
	return fmt.Sprintf("%x", hashSum), nil
}

// readGhost reads the ghost file and returns tracked file data
func readGhost(ghostPath string) (map[string]fileData, error) {
	data := make(map[string]fileData)

	if _, err := os.Stat(ghostPath); os.IsNotExist(err) {
		return data, nil
	}

	yamlBytes, err := os.ReadFile(ghostPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ghost file '%s': %w", ghostPath, err)
	}

	if len(yamlBytes) == 0 {
		return data, nil
	}

	err = yaml.Unmarshal(yamlBytes, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML from '%s': %w", ghostPath, err)
	}

	return data, nil
}

// writeGhost writes tracked file data to the ghost file atomically
func writeGhost(data map[string]fileData, ghostPath string) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Write to temporary file first for atomicity
	tmpPath := ghostPath + ".tmp"
	err = os.WriteFile(tmpPath, yamlBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Rename temporary file to actual ghost file
	err = os.Rename(tmpPath, ghostPath)
	if err != nil {
		os.Remove(tmpPath) // Clean up on error
		return fmt.Errorf("failed to finalize ghost file: %w", err)
	}

	return nil
}

// needsRehash checks if a file needs rehashing based on modification time and size
func needsRehash(filePath string, stored fileData) bool {
	stat, err := os.Stat(filePath)
	if err != nil {
		return true // If we can't stat, we need to rehash
	}

	// Check if size or modification time changed
	if stat.Size() != stored.Size || !stat.ModTime().Equal(stored.Modified) {
		return true
	}

	return false
}

// addF adds or updates a file in the ghost database
func addF(filePath string, ghostPath string, forceOverwrite bool, basePath string) error {
	filename := filepath.Base(filePath)

	if shouldIgnore(filePath, basePath) {
		printf("%s[IGNORE]%s %s\n", colorYellow, colorReset, filePath)
		atomic.AddInt64(&globalStats.skipped, 1)
		return nil
	}

	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to access file '%s': %w", filePath, err)
	}

	currentHash, err := calcHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash for '%s': %w", filePath, err)
	}

	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	defer mutex.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		return err
	}

	storedData, exists := data[filename]
	if exists {
		storedHash := storedData.Blake2b
		if currentHash == storedHash {
			printf("%s[UNCHANGED]%s %s\n", colorGray, colorReset, filename)
			return nil
		} else if !forceOverwrite {
			printf("%s[WARNING]%s File '%s' already tracked with different hash\n", colorYellow, colorReset, filename)
			printf("  Existing: %s\n", storedHash)
			printf("  Current:  %s\n", currentHash)
			printf("  Overwrite? (y/n): ")

			var response string
			fmt.Scanln(&response)

			if response != "y" && response != "Y" {
				return fmt.Errorf("operation cancelled by user")
			}
		}
		atomic.AddInt64(&globalStats.modified, 1)
		printf("%s[UPDATED]%s %s\n", colorBlue, colorReset, filename)
	} else {
		atomic.AddInt64(&globalStats.added, 1)
		printf("%s[ADDED]%s %s\n", colorGreen, colorReset, filename)
	}

	data[filename] = fileData{
		Blake2b:  currentHash,
		Size:     stat.Size(),
		Modified: stat.ModTime(),
	}

	return writeGhost(data, ghostPath)
}

// processFiles handles file processing with concurrency control
func processFiles(path string, recursive bool, operation func(string, string, string) error, operationName string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, parallelism)
	var totalFiles int64

	if fileInfo.IsDir() {
		printf("%s[PROCESSING]%s Directory: %s\n", colorCyan, colorReset, path)
		dirGhostPath := filepath.Join(path, ".ghost")

		// Count files first for progress indication
		if showProgress {
			filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() && filepath.Base(filePath) != ".ghost" && filepath.Base(filePath) != ".ghostconf" {
					atomic.AddInt64(&totalFiles, 1)
				}
				return nil
			})
		}

		var processed int64

		if recursive {
			err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					printf("%s[ERROR]%s Walking directory: %v\n", colorRed, colorReset, err)
					return nil // Continue walking despite errors
				}

				if !d.IsDir() && filepath.Base(filePath) != ".ghost" && filepath.Base(filePath) != ".ghostconf" {
					wg.Add(1)
					sem <- struct{}{}
					go func(filePath string) {
						defer wg.Done()
						defer func() { <-sem }()

						current := atomic.AddInt64(&processed, 1)
						if showProgress && totalFiles > 0 {
							printProgress(current, totalFiles, operationName)
						}

						dirPath := filepath.Dir(filePath)
						localGhostPath := filepath.Join(dirPath, ".ghost")
						if err := operation(filePath, localGhostPath, path); err != nil {
							clearProgress()
							printf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
							atomic.AddInt64(&globalStats.errors, 1)
						}
					}(filePath)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error processing directory recursively: %w", err)
			}
		} else {
			files, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("failed to read directory '%s': %w", path, err)
			}

			for _, file := range files {
				if !file.IsDir() && file.Name() != ".ghost" && file.Name() != ".ghostconf" {
					wg.Add(1)
					sem <- struct{}{}
					go func(file os.DirEntry) {
						defer wg.Done()
						defer func() { <-sem }()

						current := atomic.AddInt64(&processed, 1)
						if showProgress && totalFiles > 0 {
							printProgress(current, totalFiles, operationName)
						}

						filePath := filepath.Join(path, file.Name())
						if err := operation(filePath, dirGhostPath, path); err != nil {
							clearProgress()
							printf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
							atomic.AddInt64(&globalStats.errors, 1)
						}
					}(file)
				}
			}
		}

		wg.Wait()
		clearProgress()
		printf("%s[SAVED]%s Ghost file: %s\n", colorGreen, colorReset, dirGhostPath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	err = operation(path, fileGhostPath, dirPath)
	if err != nil {
		return err
	}

	printf("%s[SAVED]%s Ghost file: %s\n", colorGreen, colorReset, fileGhostPath)
	return nil
}

// add adds files to tracking
func add(path string, recursive bool, forceOverwrite bool) error {
	return processFiles(path, recursive, func(filePath, ghostPath, basePath string) error {
		return addF(filePath, ghostPath, forceOverwrite, basePath)
	}, "add")
}

// delF removes a file from the ghost database
func delF(filePath string, ghostPath string, basePath string) error {
	filename := filepath.Base(filePath)

	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	defer mutex.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		return err
	}

	if _, exists := data[filename]; !exists {
		return fmt.Errorf("file '%s' not found in ghost", filename)
	}

	delete(data, filename)
	atomic.AddInt64(&globalStats.deleted, 1)

	printf("%s[DELETED]%s %s\n", colorRed, colorReset, filename)

	return writeGhost(data, ghostPath)
}

// del removes files from tracking
func del(path string, recursive bool) error {
	return processFiles(path, recursive, delF, "delete")
}

// checkF verifies a file's integrity against the ghost database
func checkF(filePath string, ghostPath string, basePath string) error {
	filename := filepath.Base(filePath)

	if shouldIgnore(filePath, basePath) {
		atomic.AddInt64(&globalStats.skipped, 1)
		return nil
	}

	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	data, err := readGhost(ghostPath)
	mutex.Unlock()

	if err != nil {
		atomic.AddInt64(&globalStats.errors, 1)
		return err
	}

	storedData, exists := data[filename]
	if !exists {
		printf("%s[NOT TRACKED]%s %s\n", colorYellow, colorReset, filename)
		return nil
	}

	// Optimization: Skip hashing if file hasn't changed (unless force check is enabled)
	if !forceCheck && !needsRehash(filePath, storedData) {
		atomic.AddInt64(&globalStats.checked, 1)
		atomic.AddInt64(&globalStats.ok, 1)
		printf("%s[OK]%s %s %s(cached)%s\n", colorGreen, colorReset, filename, colorGray, colorReset)
		return nil
	}

	currentHash, err := calcHash(filePath)
	if err != nil {
		atomic.AddInt64(&globalStats.errors, 1)
		return fmt.Errorf("failed to calculate hash for '%s': %w", filePath, err)
	}

	atomic.AddInt64(&globalStats.checked, 1)

	storedHash := storedData.Blake2b

	if currentHash == storedHash {
		atomic.AddInt64(&globalStats.ok, 1)
		printf("%s[OK]%s %s\n", colorGreen, colorReset, filename)
	} else {
		atomic.AddInt64(&globalStats.corrupted, 1)
		printf("%s[CORRUPTED]%s %s\n", colorRed, colorReset, filename)
		printf("  Expected: %s\n", storedHash)
		printf("  Current:  %s\n", currentHash)
	}

	return nil
}

// check verifies file integrity
func check(path string, recursive bool) error {
	return processFiles(path, recursive, checkF, "check")
}

// cleanF removes entries for non-existent files from ghost database
func cleanF(dirPath string, ghostPath string, basePath string) error {
	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	defer mutex.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		return fmt.Errorf("failed to read ghost file: %w", err)
	}

	if len(data) == 0 {
		printf("%s[INFO]%s Ghost file is empty: %s\n", colorCyan, colorReset, ghostPath)
		return nil
	}

	removedCount := 0
	for filename := range data {
		filePath := filepath.Join(dirPath, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			printf("%s[MISSING]%s %s\n", colorYellow, colorReset, filename)
			delete(data, filename)
			removedCount++
		}
	}

	if removedCount > 0 {
		printf("%s[CLEANED]%s Removed %d missing file(s)\n", colorGreen, colorReset, removedCount)
		return writeGhost(data, ghostPath)
	}

	printf("%s[OK]%s No missing files found\n", colorGreen, colorReset)
	return nil
}

// clean removes entries for deleted files
func clean(path string, recursive bool) error {
	return processFiles(path, recursive, cleanF, "clean")
}

// updateGhostFile updates old .ghost files to include size and modified metadata
func updateGhostFile(ghostPath string, dirPath string) error {
	printf("%s[UPDATING]%s Ghost file: %s\n", colorCyan, colorReset, ghostPath)

	mutex := getGhostMutex(ghostPath)
	mutex.Lock()
	defer mutex.Unlock()

	data, err := readGhost(ghostPath)
	if err != nil {
		return fmt.Errorf("failed to read ghost file: %w", err)
	}

	if len(data) == 0 {
		printf("%s[INFO]%s Ghost file is empty: %s\n", colorCyan, colorReset, ghostPath)
		return nil
	}

	updatedCount := 0
	missingCount := 0
	corruptedCount := 0

	for filename, fileInfo := range data {
		// Check if metadata is already present
		if fileInfo.Size != 0 || !fileInfo.Modified.IsZero() {
			printf("%s[SKIP]%s %s %s(already has metadata)%s\n", colorGray, colorReset, filename, colorGray, colorReset)
			continue
		}

		filePath := filepath.Join(dirPath, filename)
		stat, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				printf("%s[MISSING]%s %s %s(file not found, keeping hash only)%s\n", colorYellow, colorReset, filename, colorGray, colorReset)
				missingCount++
			} else {
				printf("%s[ERROR]%s %s: %v\n", colorRed, colorReset, filename, err)
				atomic.AddInt64(&globalStats.errors, 1)
			}
			continue
		}

		// Verify hash before updating
		printf("%s[VERIFYING]%s %s...\n", colorCyan, colorReset, filename)
		currentHash, err := calcHash(filePath)
		if err != nil {
			printf("%s[ERROR]%s Failed to calculate hash for '%s': %v\n", colorRed, colorReset, filename, err)
			atomic.AddInt64(&globalStats.errors, 1)
			continue
		}

		// Check if hash matches
		if currentHash != fileInfo.Blake2b {
			printf("%s[HASH MISMATCH]%s %s %s(file has been modified, not updating)%s\n", colorRed, colorReset, filename, colorGray, colorReset)
			printf("  Expected: %s\n", fileInfo.Blake2b)
			printf("  Current:  %s\n", currentHash)
			corruptedCount++
			atomic.AddInt64(&globalStats.corrupted, 1)
			continue
		}

		// Hash is valid, update with size and modification time
		data[filename] = fileData{
			Blake2b:  fileInfo.Blake2b,
			Size:     stat.Size(),
			Modified: stat.ModTime(),
		}

		printf("%s[UPDATED]%s %s %s(metadata added, hash verified)%s\n", colorGreen, colorReset, filename, colorGray, colorReset)
		updatedCount++
		atomic.AddInt64(&globalStats.updated, 1)
	}

	if updatedCount > 0 {
		err = writeGhost(data, ghostPath)
		if err != nil {
			return fmt.Errorf("failed to write updated ghost file: %w", err)
		}
		printf("%s[SUCCESS]%s Updated %d file(s) in ghost database\n", colorGreen, colorReset, updatedCount)
	} else {
		printf("%s[INFO]%s No files needed updating\n", colorCyan, colorReset)
	}

	if missingCount > 0 {
		printf("%s[WARNING]%s %d tracked file(s) not found on disk\n", colorYellow, colorReset, missingCount)
	}

	if corruptedCount > 0 {
		printf("%s[WARNING]%s %d file(s) failed hash verification and were not updated\n", colorRed, colorReset, corruptedCount)
	}

	return nil
}

// update updates old .ghost files to include metadata
func update(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path '%s': %w", path, err)
	}

	if fileInfo.IsDir() {
		if recursive {
			// Walk directory tree and update all .ghost files
			return filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					printf("%s[ERROR]%s Walking directory: %v\n", colorRed, colorReset, err)
					return nil
				}

				if !d.IsDir() && d.Name() == ".ghost" {
					dirPath := filepath.Dir(filePath)
					if err := updateGhostFile(filePath, dirPath); err != nil {
						printf("%s[ERROR]%s %v\n", colorRed, colorReset, err)
						atomic.AddInt64(&globalStats.errors, 1)
					}
					fmt.Println()
				}
				return nil
			})
		} else {
			// Update .ghost file in the specified directory
			ghostPath := filepath.Join(path, ".ghost")
			if _, err := os.Stat(ghostPath); os.IsNotExist(err) {
				return fmt.Errorf("no .ghost file found in directory: %s", path)
			}
			return updateGhostFile(ghostPath, path)
		}
	}

	// If path is a .ghost file directly
	if filepath.Base(path) == ".ghost" {
		dirPath := filepath.Dir(path)
		return updateGhostFile(path, dirPath)
	}

	return fmt.Errorf("path must be a directory or a .ghost file")
}

// printSummary displays operation statistics
func printSummary() {
	elapsed := time.Since(startTime)

	fmt.Println()
	fmt.Printf("%s╔═══════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║%s              OPERATION SUMMARY                %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)
	fmt.Printf("%s╠═══════════════════════════════════════════════╣%s\n", colorCyan, colorReset)

	if globalStats.checked > 0 {
		fmt.Printf("%s║%s  Checked:    %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorBlue, globalStats.checked, colorReset, colorCyan, colorReset)
		fmt.Printf("%s║%s  OK:         %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorGreen, globalStats.ok, colorReset, colorCyan, colorReset)
		fmt.Printf("%s║%s  Corrupted:  %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorRed, globalStats.corrupted, colorReset, colorCyan, colorReset)
	}

	if globalStats.added > 0 {
		fmt.Printf("%s║%s  Added:      %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorGreen, globalStats.added, colorReset, colorCyan, colorReset)
	}

	if globalStats.modified > 0 {
		fmt.Printf("%s║%s  Modified:   %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorBlue, globalStats.modified, colorReset, colorCyan, colorReset)
	}

	if globalStats.updated > 0 {
		fmt.Printf("%s║%s  Updated:    %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorGreen, globalStats.updated, colorReset, colorCyan, colorReset)
	}

	if globalStats.deleted > 0 {
		fmt.Printf("%s║%s  Deleted:    %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorRed, globalStats.deleted, colorReset, colorCyan, colorReset)
	}

	if globalStats.skipped > 0 {
		fmt.Printf("%s║%s  Skipped:    %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorYellow, globalStats.skipped, colorReset, colorCyan, colorReset)
	}

	if globalStats.errors > 0 {
		fmt.Printf("%s║%s  Errors:     %s%-6d%s                           %s║%s\n",
			colorCyan, colorReset, colorRed, globalStats.errors, colorReset, colorCyan, colorReset)
	}

	fmt.Printf("%s║%s  Duration:   %-29s    %s║%s\n",
		colorCyan, colorReset, elapsed.Round(time.Millisecond).String(), colorCyan, colorReset)
	fmt.Printf("%s╚═══════════════════════════════════════════════╝%s\n", colorCyan, colorReset)
}

// help displays usage information
func help() {
	fmt.Printf("%s╔══════════════════════════════════════════════════════════╗%s\n", colorMagenta, colorReset)
	fmt.Printf("%s║                    dataGhost v2.0                        ║%s\n", colorMagenta, colorReset)
	fmt.Printf("%s║            File Integrity Tracking Utility               ║%s\n", colorMagenta, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════╝%s\n\n", colorMagenta, colorReset)

	fmt.Printf("%sUSAGE:%s\n", colorCyan, colorReset)
	fmt.Println("  dataGhost [OPTIONS] COMMAND [PATH]")
	fmt.Println()

	fmt.Printf("%sCOMMANDS:%s\n", colorCyan, colorReset)
	fmt.Printf("  %sadd%s       Add files to tracking\n", colorGreen, colorReset)
	fmt.Printf("  %sdel%s       Remove files from tracking\n", colorRed, colorReset)
	fmt.Printf("  %scheck%s     Verify file integrity\n", colorBlue, colorReset)
	fmt.Printf("  %sclean%s     Remove missing file entries\n", colorYellow, colorReset)
	fmt.Printf("  %supdate%s    Update old .ghost files with metadata\n", colorMagenta, colorReset)
	fmt.Println()

	fmt.Printf("%sOPTIONS:%s\n", colorCyan, colorReset)
	fmt.Println("  -c              Load .ghostconf from target directory")
	fmt.Println("  -cs             Load .ghostconf (strict mode)")
	fmt.Println("  -cf FILE        Load config from specified file")
	fmt.Println("  -csf FILE       Load config from file (strict mode)")
	fmt.Println("  -r              Process directories recursively")
	fmt.Println("  -q              Quiet mode (minimal output)")
	fmt.Println("  -p N            Number of parallel workers")
	fmt.Println("  -f              Force operations without prompts")
	fmt.Println("  -fc             Force hash calculation (ignore cache)")
	fmt.Println()

	fmt.Printf("%sCONFIG FILE EXAMPLE (.ghostconf):%s\n", colorCyan, colorReset)
	fmt.Println("  ignore:")
	fmt.Println("    - \"*.tmp\"")
	fmt.Println("    - \"*.log\"")
	fmt.Println("    - \"node_modules/\"")
	fmt.Println("    - \".git/\"")
	fmt.Println("  buffer: 262144")
	fmt.Println("  parallel: 4")
	fmt.Println("  show_progress: true")
	fmt.Println()

	fmt.Printf("%sEXAMPLES:%s\n", colorCyan, colorReset)
	fmt.Println("  dataGhost add file.txt")
	fmt.Println("  dataGhost -r check .")
	fmt.Println("  dataGhost -c -r add /path/to/dir")
	fmt.Println("  dataGhost -q check . && echo \"All files OK\"")
	fmt.Println("  dataGhost -fc check .")
	fmt.Println("  dataGhost update .ghost")
	fmt.Println("  dataGhost -r update .")
	fmt.Println()

	fmt.Printf("%sEXIT CODES:%s\n", colorCyan, colorReset)
	fmt.Println("  0  Success")
	fmt.Println("  1  Corruption detected")
	fmt.Println("  2  Error occurred")
}

func main() {
	startTime = time.Now()

	var useConfig bool
	var useStrictConfig bool
	var configFile string
	var strictConfigFile string

	flag.BoolVar(&useConfig, "c", false, "Load .ghostconf from target directory")
	flag.BoolVar(&useStrictConfig, "cs", false, "Load .ghostconf (strict mode)")
	flag.StringVar(&configFile, "cf", "", "Load config from file")
	flag.StringVar(&strictConfigFile, "csf", "", "Load config from file (strict mode)")
	flag.IntVar(&parallelism, "p", 1, "Number of parallel workers")
	flag.BoolVar(&quietMode, "q", false, "Quiet mode")
	recursive := flag.Bool("r", false, "Process recursively")
	forceOverwrite := flag.Bool("f", false, "Force operations")
	flag.BoolVar(&forceCheck, "fc", false, "Force hash calculation (ignore cache)")
	flag.Parse()

	if flag.NArg() < 2 {
		help()
		os.Exit(2)
	}

	command := flag.Arg(0)
	path := flag.Arg(1)

	finalConfigFile := ""
	useAnyConfig := false

	if strictConfigFile != "" {
		strictConfig = true
		finalConfigFile = strictConfigFile
		useAnyConfig = true
	} else if configFile != "" {
		finalConfigFile = configFile
		useAnyConfig = true
	} else if useStrictConfig {
		strictConfig = true
		useAnyConfig = true
	} else if useConfig {
		useAnyConfig = true
	}

	if err := loadConfig(finalConfigFile, path, useAnyConfig, useAnyConfig); err != nil {
		fmt.Printf("%s[FATAL]%s Failed to load config: %v\n", colorRed, colorReset, err)
		os.Exit(2)
	}

	// Apply CLI overrides
	if flag.Lookup("p").Value.String() != "1" {
		rootConfig.Parallel = parallelism
	} else {
		parallelism = rootConfig.Parallel
	}

	if flag.Lookup("q").Value.String() == "true" {
		rootConfig.Quiet = true
	}
	quietMode = rootConfig.Quiet

	if flag.Lookup("r").Value.String() == "true" {
		rootConfig.Recursive = true
	} else {
		*recursive = rootConfig.Recursive
	}

	if flag.Lookup("f").Value.String() == "true" {
		rootConfig.Force = true
	} else {
		*forceOverwrite = rootConfig.Force
	}

	showProgress = rootConfig.ShowProgress && !quietMode

	var err error
	switch command {
	case "add":
		err = add(path, *recursive, *forceOverwrite)
	case "del":
		err = del(path, *recursive)
	case "check":
		err = check(path, *recursive)
		printSummary()
		if globalStats.corrupted > 0 {
			os.Exit(1)
		}
	case "clean":
		err = clean(path, *recursive)
	case "update":
		err = update(path, *recursive)
		printSummary()
		if globalStats.corrupted > 0 {
			os.Exit(1)
		}
	default:
		fmt.Printf("%s[ERROR]%s Unknown command: %s\n", colorRed, colorReset, command)
		help()
		os.Exit(2)
	}

	if err != nil {
		fmt.Printf("%s[FATAL]%s %v\n", colorRed, colorReset, err)
		os.Exit(2)
	}

	if !quietMode && command != "check" && command != "update" {
		printSummary()
	}

	os.Exit(0)
}
