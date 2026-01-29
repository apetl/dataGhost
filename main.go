package main

import (
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/edsrzf/mmap-go"
	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/blake2b"
)

// --- Configuration & Stats ---

type fileData struct {
	Blake2b  string    `yaml:"Blake2b"`
	Size     int64     `yaml:"size,omitempty"`
	Modified time.Time `yaml:"modified,omitempty"`
}

type conf struct {
	Ignore       []string `yaml:"ignore"`
	Buffer       int      `yaml:"buffer"`
	Quiet        bool     `yaml:"quiet"`
	Parallel     int      `yaml:"parallel"`
	Force        bool     `yaml:"force"`
	ShowProgress bool     `yaml:"show_progress"`
}

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

// --- Engine Types ---

type DirJob struct {
	DirPath   string
	Files     []string
	GhostPath string
	BasePath  string
}

type Engine struct {
	config       conf
	strictConfig bool
	forceCheck   bool
	recursive    bool
	rootPath     string
	cmd          string
	stats        *stats
	program      *tea.Program
}

// --- TUI Types ---

type jobStartMsg struct{}
type jobEndMsg struct{}
type progressMsg int64
type logMsg string

type model struct {
	engine    *Engine
	progress  progress.Model
	processed int64
	logs      []string
	quitting  bool
	width     int
	height    int
}

// --- Globals & Constants ---

const (
	minBuffer     = 64 * 1024
	defaultBuffer = 256 * 1024
	maxBuffer     = 1024 * 1024
	mmapThreshold = 10 * 1024 * 1024
)

var (
	// Pools
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

	// Caches
	configCache = sync.Map{}

	// Styles
	styleErr     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleOk      = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	styleWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	styleInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	styleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Bold(true)
	styleTitle   = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

// --- Helper Functions ---

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

func loadConfigFromFile(configPath string) (conf, error) {
	config := getDefaultConfig()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil
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

func getConfigForPath(dirPath string, rootConfig conf, strict bool) conf {
	if strict {
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

func isIgnored(path, basePath string, isDir bool, rootConfig conf, strict bool) bool {
	dir := filepath.Dir(path)
	if isDir {
		dir = path
	}
	config := getConfigForPath(dir, rootConfig, strict)
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

func getBufferSize(fileSize int64, configBuffer int) int {
	if configBuffer > 0 {
		return configBuffer
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
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to mmap: %w", err)
	}
	defer func() {
		data.Unmap()
	}()

	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func calcHash(path string, bufferSize int) (string, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat: %w", err)
	}
	if stat.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symlink")
	}

	fileSize := stat.Size()
	if fileSize > mmapThreshold {
		hashStr, err := calcHashMmap(path)
		if err == nil {
			return hashStr, nil
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open: %w", err)
	}
	defer file.Close()

	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buffer := *bufPtr
	bufSize := getBufferSize(fileSize, bufferSize)
	if cap(buffer) < bufSize {
		buffer = make([]byte, bufSize)
	} else {
		buffer = buffer[:bufSize]
	}

	if _, err := io.CopyBuffer(h, file, buffer); err != nil {
		return "", fmt.Errorf("failed to read: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func readGhost(ghostPath string) (map[string]fileData, error) {
	data := make(map[string]fileData)
	yamlBytes, err := os.ReadFile(ghostPath)
	if os.IsNotExist(err) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	if len(yamlBytes) == 0 {
		return data, nil
	}
	if err := yaml.Unmarshal(yamlBytes, &data); err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}
	return data, nil
}

func writeGhost(data map[string]fileData, ghostPath string) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	tmpPath := ghostPath + ".tmp"
	if err := os.WriteFile(tmpPath, yamlBytes, 0644); err != nil {
		return fmt.Errorf("write temp failed: %w", err)
	}

	if err := os.Rename(tmpPath, ghostPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename failed: %w", err)
	}
	return nil
}

func needsRehash(stat os.FileInfo, stored fileData) bool {
	return stat.Size() != stored.Size || !stat.ModTime().Equal(stored.Modified)
}

// --- Engine Logic ---

func (e *Engine) Start() tea.Cmd {
	return func() tea.Msg {
		e.program.Send(jobStartMsg{})

		jobs := make(chan DirJob, 100)
		var scanWg sync.WaitGroup
		var workerWg sync.WaitGroup

		numWorkers := e.config.Parallel
		if numWorkers < 1 {
			numWorkers = 1
		}

		workerWg.Add(numWorkers)
		for i := 0; i < numWorkers; i++ {
			go func() {
				defer workerWg.Done()
				e.worker(jobs)
			}()
		}

		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			e.scanDirectory(e.rootPath, jobs)
		}()

		scanWg.Wait()
		close(jobs)
		workerWg.Wait()

		return jobEndMsg{}
	}
}

func (e *Engine) scanDirectory(path string, jobs chan<- DirJob) {
	entries, err := os.ReadDir(path)
	if err != nil {
		e.program.Send(logMsg(fmt.Sprintf("%s Accessing '%s': %v", styleErr.Render("[ERROR]"), path, err)))
		return
	}

	var files []string
	var subdirs []string

	for _, entry := range entries {
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" {
				if isIgnored(filepath.Join(path, entry.Name()), e.rootPath, true, e.config, e.strictConfig) {
					continue
				}
			}
			subdirs = append(subdirs, entry.Name())
		} else {
			files = append(files, entry.Name())
		}
	}

	if isIgnored(path, e.rootPath, true, e.config, e.strictConfig) {
		return
	}

	// For clean and update, we care about the ghost file primarily
	hasGhost := false
	ghostPath := filepath.Join(path, ".ghost")
	if _, err := os.Stat(ghostPath); err == nil {
		hasGhost = true
	}

	validFiles := []string{}
	for _, f := range files {
		if f == ".ghost" || f == ".ghostconf" {
			continue
		}
		fullPath := filepath.Join(path, f)
		if !isIgnored(fullPath, e.rootPath, false, e.config, e.strictConfig) {
			validFiles = append(validFiles, f)
		}
	}

	shouldProcess := false
	if e.cmd == "add" || e.cmd == "check" || e.cmd == "del" {
		if len(validFiles) > 0 {
			shouldProcess = true
		}
	} else if e.cmd == "clean" || e.cmd == "update" {
		if hasGhost {
			shouldProcess = true
		}
	}

	if shouldProcess {
		jobs <- DirJob{
			DirPath:   path,
			Files:     validFiles, // For clean, this might be partial list of files on disk
			GhostPath: ghostPath,
			BasePath:  e.rootPath,
		}
	}

	if e.recursive {
		for _, sub := range subdirs {
			e.scanDirectory(filepath.Join(path, sub), jobs)
		}
	}
}

func (e *Engine) worker(jobs <-chan DirJob) {
	for job := range jobs {
		data, err := readGhost(job.GhostPath)
		if err != nil {
			e.program.Send(logMsg(fmt.Sprintf("%s Reading ghost %s: %v", styleErr.Render("[ERROR]"), job.GhostPath, err)))
			e.stats.errors.Add(1)
			continue
		}

		dirty := false

		switch e.cmd {
		case "add":
			for _, filename := range job.Files {
				filePath := filepath.Join(job.DirPath, filename)
				stat, err := os.Stat(filePath)
				if err != nil {
					e.program.Send(logMsg(fmt.Sprintf("%s Accessing %s: %v", styleErr.Render("[ERROR]"), filename, err)))
					e.stats.errors.Add(1)
					continue
				}

				hashVal, err := calcHash(filePath, e.config.Buffer)
				if err != nil {
					e.program.Send(logMsg(fmt.Sprintf("%s Hashing %s: %v", styleErr.Render("[ERROR]"), filename, err)))
					e.stats.errors.Add(1)
					continue
				}

				if stored, exists := data[filename]; exists {
					if stored.Blake2b == hashVal {
						// e.program.Send(logMsg(fmt.Sprintf("%s %s", styleDim.Render("[UNCHANGED]"), filename)))
						// Too verbose for unchanged?
					} else {
						if !e.config.Force {
							e.program.Send(logMsg(fmt.Sprintf("%s %s (use -f to overwrite)", styleWarn.Render("[CONFLICT]"), filename)))
							continue
						}
						data[filename] = fileData{Blake2b: hashVal, Size: stat.Size(), Modified: stat.ModTime()}
						dirty = true
						e.stats.modified.Add(1)
						e.program.Send(logMsg(fmt.Sprintf("%s %s", styleInfo.Render("[UPDATED]"), filename)))
					}
				} else {
					data[filename] = fileData{Blake2b: hashVal, Size: stat.Size(), Modified: stat.ModTime()}
					dirty = true
					e.stats.added.Add(1)
					e.program.Send(logMsg(fmt.Sprintf("%s %s", styleSuccess.Render("[ADDED]"), filename)))
				}
				e.program.Send(progressMsg(1))
			}

		case "del":
			for _, filename := range job.Files {
				if _, exists := data[filename]; exists {
					delete(data, filename)
					dirty = true
					e.stats.deleted.Add(1)
					e.program.Send(logMsg(fmt.Sprintf("%s %s", styleErr.Render("[DELETED]"), filename)))
				} else {
					e.program.Send(logMsg(fmt.Sprintf("%s %s not tracked", styleWarn.Render("[NOT FOUND]"), filename)))
				}
				e.program.Send(progressMsg(1))
			}

		case "check":
			for _, filename := range job.Files {
				filePath := filepath.Join(job.DirPath, filename)
				stored, exists := data[filename]
				if !exists {
					e.program.Send(logMsg(fmt.Sprintf("%s %s", styleWarn.Render("[NOT TRACKED]"), filename)))
					e.program.Send(progressMsg(1))
					continue
				}
				e.stats.checked.Add(1)

				stat, err := os.Stat(filePath)
				if err != nil {
					e.stats.errors.Add(1)
					e.program.Send(progressMsg(1))
					continue
				}

				if !e.forceCheck && !needsRehash(stat, stored) {
					e.stats.ok.Add(1)
					// e.program.Send(logMsg(fmt.Sprintf("%s %s", styleOk.Render("[OK]"), filename)))
					e.program.Send(progressMsg(1))
					continue
				}

				hashVal, err := calcHash(filePath, e.config.Buffer)
				if err != nil {
					e.stats.errors.Add(1)
					e.program.Send(logMsg(fmt.Sprintf("%s Hashing %s: %v", styleErr.Render("[ERROR]"), filename, err)))
					e.program.Send(progressMsg(1))
					continue
				}

				if hashVal == stored.Blake2b {
					e.stats.ok.Add(1)
					// e.program.Send(logMsg(fmt.Sprintf("%s %s", styleOk.Render("[OK]"), filename)))
				} else {
					e.stats.corrupted.Add(1)
					e.program.Send(logMsg(fmt.Sprintf("%s %s", styleErr.Render("[CORRUPTED]"), filename)))
				}
				e.program.Send(progressMsg(1))
			}

		case "clean":
			toDelete := []string{}
			for filename := range data {
				fp := filepath.Join(job.DirPath, filename)
				if _, err := os.Stat(fp); os.IsNotExist(err) {
					toDelete = append(toDelete, filename)
				}
			}
			for _, f := range toDelete {
				delete(data, f)
				dirty = true
				e.stats.deleted.Add(1)
				e.program.Send(logMsg(fmt.Sprintf("%s Removed entry for %s", styleWarn.Render("[CLEANED]"), f)))
			}

		case "update":
			updatedCount := 0
			for filename, info := range data {
				if info.Size != 0 || !info.Modified.IsZero() {
					continue
				}
				fp := filepath.Join(job.DirPath, filename)
				stat, err := os.Stat(fp)
				if err != nil { continue }

				h, err := calcHash(fp, e.config.Buffer)
				if err != nil || h != info.Blake2b {
					continue
				}

				data[filename] = fileData{Blake2b: info.Blake2b, Size: stat.Size(), Modified: stat.ModTime()}
				dirty = true
				updatedCount++
				e.stats.updated.Add(1)
			}
			if updatedCount > 0 {
				e.program.Send(logMsg(fmt.Sprintf("%s Updated metadata for %d files in %s", styleInfo.Render("[UPDATED]"), updatedCount, job.DirPath)))
			}
		}

		if dirty {
			if err := writeGhost(data, job.GhostPath); err != nil {
				e.program.Send(logMsg(fmt.Sprintf("%s Writing ghost %s: %v", styleErr.Render("[ERROR]"), job.GhostPath, err)))
				e.stats.errors.Add(1)
			}
		}
	}
}

// --- TUI Methods ---

func (m model) Init() tea.Cmd {
	return m.engine.Start()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
			m.quitting = true
			return m, tea.Quit
		}
	case jobStartMsg:
		return m, nil
	case jobEndMsg:
		m.quitting = true
		return m, tea.Quit
	case progressMsg:
		m.processed += int64(msg)
		return m, nil
	case logMsg:
		m.logs = append(m.logs, string(msg))
		if len(m.logs) > 10 {
			m.logs = m.logs[1:]
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	s := styleTitle.Render(fmt.Sprintf("DataGhost: %s", strings.ToUpper(m.engine.cmd))) + "\n\n"

	for _, l := range m.logs {
		s += l + "\n"
	}
	if len(m.logs) == 0 {
		s += styleDim.Render("Waiting for events...") + "\n"
	}

	s += "\n"
	s += fmt.Sprintf("Processed items: %d", m.processed)
	s += "\n\n" + styleDim.Render("Press Ctrl+C to quit")
	return s
}

// --- Main ---

func printSummary(stats *stats, duration time.Duration) {
	const innerWidth = 43
	topBorder := colorBlue + "╔" + strings.Repeat("═", innerWidth) + "╗" + colorReset
	midBorder := colorBlue + "╠" + strings.Repeat("═", innerWidth) + "╣" + colorReset
	botBorder := colorBlue + "╚" + strings.Repeat("═", innerWidth) + "╝" + colorReset
	border := colorBlue + "║" + colorReset

	fmt.Println()
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

	if val := stats.checked.Load(); val > 0 {
		printDataLine("Checked:", fmt.Sprintf("%d", val), colorCyan)
	}
	if val := stats.ok.Load(); val > 0 {
		printDataLine("OK:", fmt.Sprintf("%d", val), colorGreen)
	}
	if val := stats.corrupted.Load(); val > 0 {
		printDataLine("Corrupted:", fmt.Sprintf("%d", val), colorRed)
	}
	if val := stats.added.Load(); val > 0 {
		printDataLine("Added:", fmt.Sprintf("%d", val), colorGreen)
	}
	if val := stats.modified.Load(); val > 0 {
		printDataLine("Modified:", fmt.Sprintf("%d", val), colorBlue)
	}
	if val := stats.updated.Load(); val > 0 {
		printDataLine("Updated:", fmt.Sprintf("%d", val), colorGreen)
	}
	if val := stats.deleted.Load(); val > 0 {
		printDataLine("Deleted:", fmt.Sprintf("%d", val), colorRed)
	}
	if val := stats.skipped.Load(); val > 0 {
		printDataLine("Skipped:", fmt.Sprintf("%d", val), colorYellow)
	}
	if val := stats.errors.Load(); val > 0 {
		printDataLine("Errors:", fmt.Sprintf("%d", val), colorRed)
	}
	printDataLine("Duration:", duration.String(), "")
	fmt.Println(botBorder)
}

func help() {
	fmt.Print(
		colorBlue + "╔══════════════════════════════════════════════════════════╗" + colorReset + "\n" +
			colorBlue + "║                    dataGhost v2.1                        ║" + colorReset + "\n" +
			colorBlue + "║            File Integrity Tracking Utility               ║" + colorReset + "\n" +
			colorBlue + "╚══════════════════════════════════════════════════════════╝" + colorReset + "\n\n" +
			colorYellow + "USAGE:" + colorReset + "\n" +
			"  dataGhost [OPTIONS] COMMAND " + colorGray + "[PATH]" + colorReset + "\n\n" +
			colorYellow + "COMMANDS:" + colorReset + "\n" +
			"  add, del, check, clean, update\n\n" +
			colorYellow + "OPTIONS:" + colorReset + "\n" +
			"  -c, -cs, -cf, -csf  Config loading options\n" +
			"  -r                  Recursive\n" +
			"  -p N                Parallel workers\n" +
			"  -f                  Force overwrite\n" +
			"  -fc                 Force hash check\n" +
			"  -q                  Quiet mode\n",
	)
}

func isFlagSet(name string) bool {
	wasSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

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

func main() {
	startTime := time.Now()

	var (
		useConfig        bool
		useStrictConfig  bool
		configFile       string
		strictConfigFile string
		parallelism      int
		quietMode        bool
		recursive        bool
		forceOverwrite   bool
		forceCheck       bool
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

	// Config Logic
	useAnyConfig := useConfig || useStrictConfig || configFile != "" || strictConfigFile != ""
	isStrict := useStrictConfig || strictConfigFile != ""
	finalConfigFile := ""
	if strictConfigFile != "" {
		finalConfigFile = strictConfigFile
	} else if configFile != "" {
		finalConfigFile = configFile
	}

	// Helper to load root config
	var rootConfig conf
	if err := func() error {
		config := getDefaultConfig()
		if !useAnyConfig {
			rootConfig = config
			return nil
		}

		cp := finalConfigFile
		if cp == "" {
			abs, err := filepath.Abs(path)
			if err != nil { return err }
			stat, err := os.Stat(abs)
			if err != nil { return err }
			rootDir := abs
			if !stat.IsDir() { rootDir = filepath.Dir(abs) }
			cp = filepath.Join(rootDir, ".ghostconf")
		}

		loaded, err := loadConfigFromFile(cp)
		if err != nil { return err }
		rootConfig = loaded
		return nil
	}(); err != nil {
		fmt.Printf("%s[FATAL]%s Failed to load config: %v\n", colorRed, colorReset, err)
		os.Exit(2)
	}

	// CLI Overrides
	if isFlagSet("p") {
		if parallelism < 1 { parallelism = 1 }
		rootConfig.Parallel = parallelism
	}
	if rootConfig.Parallel < 1 { rootConfig.Parallel = 1 }
	if isFlagSet("q") { rootConfig.Quiet = quietMode }
	if isFlagSet("f") { rootConfig.Force = forceOverwrite }

	stats := &stats{}
	engine := &Engine{
		config:       rootConfig,
		strictConfig: isStrict,
		forceCheck:   forceCheck,
		recursive:    recursive,
		rootPath:     path,
		cmd:          command,
		stats:        stats,
	}

	// Initialize Model
	m := model{
		engine: engine,
		logs:   make([]string, 0),
	}

	// Create Program
	p := tea.NewProgram(m)
	engine.program = p

	// Run
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(2)
	}

	// Summary
	if !rootConfig.Quiet {
		printSummary(stats, time.Since(startTime))
	}

	if stats.errors.Load() > 0 || stats.corrupted.Load() > 0 {
		os.Exit(1)
	}
}
