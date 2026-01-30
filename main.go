package main

import (
	"encoding/hex"
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

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
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

type appState int

const (
	stateRunning appState = iota
	stateDone
)

type jobStartMsg struct{}
type jobEndMsg struct{}
type progressMsg int64

// ResultType defines the category of a result
type ResultType int

const (
	ResInfo ResultType = iota
	ResSuccess
	ResWarn
	ResError
	ResCorrupted
)

// ResultMsg represents a significant event for a file
type ResultMsg struct {
	Type    ResultType
	Path    string
	Message string
}

type model struct {
	engine    *Engine
	state     appState
	spinner   spinner.Model
	viewport  viewport.Model
	results   []ResultMsg
	processed int64
	quitting  bool
	width     int
	height    int
	ready     bool
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
	colorRed     = lipgloss.Color("196")
	colorGreen   = lipgloss.Color("46")
	colorYellow  = lipgloss.Color("220")
	colorBlue    = lipgloss.Color("39")
	colorGray    = lipgloss.Color("240")
	colorWhite   = lipgloss.Color("255")

	styleErr     = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	styleOk      = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	styleWarn    = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	styleInfo    = lipgloss.NewStyle().Foreground(colorBlue).Bold(true)
	styleDim     = lipgloss.NewStyle().Foreground(colorGray)
	styleSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Bold(true)
	styleTitle   = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Border(lipgloss.RoundedBorder()).Padding(0, 1)
	styleStatBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).MarginRight(1)
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
	return hex.EncodeToString(h.Sum(nil)), nil
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

	return hex.EncodeToString(h.Sum(nil)), nil
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
		e.program.Send(ResultMsg{ResError, path, fmt.Sprintf("Access denied: %v", err)})
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
			Files:     validFiles,
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
			e.program.Send(ResultMsg{ResError, job.GhostPath, fmt.Sprintf("Read failed: %v", err)})
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
					e.program.Send(ResultMsg{ResError, filename, fmt.Sprintf("Stat failed: %v", err)})
					e.stats.errors.Add(1)
					continue
				}

				hashVal, err := calcHash(filePath, e.config.Buffer)
				if err != nil {
					e.program.Send(ResultMsg{ResError, filename, fmt.Sprintf("Hash failed: %v", err)})
					e.stats.errors.Add(1)
					continue
				}

				if stored, exists := data[filename]; exists {
					if stored.Blake2b == hashVal {
						// Unchanged - usually silent
					} else {
						if !e.config.Force {
							e.program.Send(ResultMsg{ResWarn, filename, "Hash mismatch (use -f to overwrite)"})
							continue
						}
						data[filename] = fileData{Blake2b: hashVal, Size: stat.Size(), Modified: stat.ModTime()}
						dirty = true
						e.stats.modified.Add(1)
						e.program.Send(ResultMsg{ResSuccess, filename, "Updated"})
					}
				} else {
					data[filename] = fileData{Blake2b: hashVal, Size: stat.Size(), Modified: stat.ModTime()}
					dirty = true
					e.stats.added.Add(1)
					e.program.Send(ResultMsg{ResSuccess, filename, "Added"})
				}
				e.program.Send(progressMsg(1))
			}

		case "del":
			for _, filename := range job.Files {
				if _, exists := data[filename]; exists {
					delete(data, filename)
					dirty = true
					e.stats.deleted.Add(1)
					e.program.Send(ResultMsg{ResWarn, filename, "Deleted from tracking"})
				} else {
					e.program.Send(ResultMsg{ResInfo, filename, "Not tracked"})
				}
				e.program.Send(progressMsg(1))
			}

		case "check":
			for _, filename := range job.Files {
				filePath := filepath.Join(job.DirPath, filename)
				stored, exists := data[filename]
				if !exists {
					e.program.Send(ResultMsg{ResWarn, filename, "Not tracked"})
					e.program.Send(progressMsg(1))
					continue
				}
				e.stats.checked.Add(1)

				stat, err := os.Stat(filePath)
				if err != nil {
					e.stats.errors.Add(1)
					e.program.Send(ResultMsg{ResError, filename, fmt.Sprintf("Stat failed: %v", err)})
					e.program.Send(progressMsg(1))
					continue
				}

				if !e.forceCheck && !needsRehash(stat, stored) {
					e.stats.ok.Add(1)
					e.program.Send(progressMsg(1))
					continue
				}

				hashVal, err := calcHash(filePath, e.config.Buffer)
				if err != nil {
					e.stats.errors.Add(1)
					e.program.Send(ResultMsg{ResError, filename, fmt.Sprintf("Hash failed: %v", err)})
					e.program.Send(progressMsg(1))
					continue
				}

				if hashVal == stored.Blake2b {
					e.stats.ok.Add(1)
				} else {
					e.stats.corrupted.Add(1)
					e.program.Send(ResultMsg{ResCorrupted, filename, fmt.Sprintf("CORRUPTED! Expected: %s", stored.Blake2b[:8])})
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
				e.program.Send(ResultMsg{ResWarn, f, "Cleaned (missing)"})
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
				e.program.Send(ResultMsg{ResInfo, job.DirPath, fmt.Sprintf("Updated metadata for %d files", updatedCount)})
			}
		}

		if dirty {
			if err := writeGhost(data, job.GhostPath); err != nil {
				e.program.Send(ResultMsg{ResError, job.GhostPath, fmt.Sprintf("Write failed: %v", err)})
				e.stats.errors.Add(1)
			}
		}
	}
}

// --- TUI Logic ---

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.engine.Start(),
		m.spinner.Tick,
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}
		if m.state == stateDone {
			if msg.String() == "q" || msg.Type == tea.KeyEsc {
				m.quitting = true
				return m, tea.Quit
			}
		}
		if m.state == stateDone {
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 12 // Reserve space for header/stats
		if !m.ready {
			m.ready = true
		}

	case jobStartMsg:
		m.state = stateRunning
		m.results = make([]ResultMsg, 0)

	case jobEndMsg:
		m.state = stateDone
		// Populate viewport with the report
		m.viewport.SetContent(m.renderReport())

	case progressMsg:
		m.processed += int64(msg)

	case ResultMsg:
		m.results = append(m.results, msg)
		if len(m.results) > 1000 { // limit history size in running view to avoid memory bloat?
			// Actually we need them for the report.
			// Maybe filtering? For now keep all.
		}

	case spinner.TickMsg:
		if m.state == stateRunning {
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.quitting {
		return ""
	}
	if !m.ready {
		return "Initializing..."
	}

	s := strings.Builder{}

	// --- Header ---
	title := fmt.Sprintf(" DataGhost: %s ", strings.ToUpper(m.engine.cmd))
	header := styleTitle.Render(title)
	if m.state == stateRunning {
		header += fmt.Sprintf(" %s Processing...", m.spinner.View())
	} else {
		header += styleOk.Render(" DONE ")
	}
	s.WriteString(header + "\n\n")

	// --- Stats Grid ---
	stats := m.engine.stats
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		styleStatBox.Render(fmt.Sprintf("Checked\n%d", stats.checked.Load())),
		styleStatBox.Render(fmt.Sprintf("Corrupted\n%s", styleErr.Render(fmt.Sprintf("%d", stats.corrupted.Load())))),
		styleStatBox.Render(fmt.Sprintf("Errors\n%s", styleErr.Render(fmt.Sprintf("%d", stats.errors.Load())))),
		styleStatBox.Render(fmt.Sprintf("OK\n%s", styleOk.Render(fmt.Sprintf("%d", stats.ok.Load())))),
	))
	s.WriteString("\n")

	// --- Body ---
	if m.state == stateRunning {
		s.WriteString(fmt.Sprintf("\nProcessed Items: %d\n\n", m.processed))
		// Show last few logs
		start := len(m.results) - 5
		if start < 0 { start = 0 }
		for i := start; i < len(m.results); i++ {
			r := m.results[i]
			prefix := ""
			switch r.Type {
			case ResError: prefix = styleErr.Render("[ERR] ")
			case ResCorrupted: prefix = styleErr.Render("[CORRUPT] ")
			case ResWarn: prefix = styleWarn.Render("[WARN] ")
			case ResSuccess: prefix = styleSuccess.Render("[OK] ")
			}
			s.WriteString(fmt.Sprintf("%s%s: %s\n", prefix, r.Path, r.Message))
		}
	} else {
		s.WriteString("\n" + styleInfo.Render("Detailed Report (Scroll with arrows, 'q' to quit):") + "\n")
		s.WriteString(m.viewport.View())
	}

	return s.String()
}

func (m model) renderReport() string {
	s := strings.Builder{}

	// Filter for interesting events
	hasIssues := false
	for _, r := range m.results {
		if r.Type == ResCorrupted || r.Type == ResError || r.Type == ResWarn {
			hasIssues = true
			prefix := ""
			switch r.Type {
			case ResError: prefix = styleErr.Render("ERROR    ")
			case ResCorrupted: prefix = styleErr.Render("CORRUPTED")
			case ResWarn: prefix = styleWarn.Render("WARNING  ")
			}
			s.WriteString(fmt.Sprintf("%s %s %s\n", prefix, r.Path, styleDim.Render(r.Message)))
		}
	}

	if !hasIssues {
		s.WriteString("\n" + styleSuccess.Render("No issues found. All operations successful.") + "\n")
	}

	return s.String()
}

// --- Main ---

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
		fmt.Println("Usage: dataGhost [options] command path")
		os.Exit(2)
	}
	command := flag.Arg(0)
	path := flag.Arg(1)

	// Config Logic (Abbreviated for brevity as logic is same)
	rootConfig := getDefaultConfig()
	// ... (Load config logic here if needed, keeping simple for this step) ...
	// To ensure full functionality we should keep the config loading logic.
	// Re-inserting config loading logic:
	useAnyConfig := useConfig || useStrictConfig || configFile != "" || strictConfigFile != ""
	isStrict := useStrictConfig || strictConfigFile != ""
	finalConfigFile := ""
	if strictConfigFile != "" { finalConfigFile = strictConfigFile } else if configFile != "" { finalConfigFile = configFile }

	if err := func() error {
		if !useAnyConfig { return nil }
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
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(2)
	}

	if isFlagSet("p") { rootConfig.Parallel = parallelism }
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

	// Spinner
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	m := model{
		engine:   engine,
		spinner:  sp,
		results:  make([]ResultMsg, 0),
		state:    stateRunning,
		viewport: viewport.New(0, 0),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	engine.program = p

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(2)
	}

	if stats.errors.Load() > 0 || stats.corrupted.Load() > 0 {
		os.Exit(1)
	}
}
