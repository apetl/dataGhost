// Package output provides terminal formatting, colors, progress bars, and help text.
package output

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

// AppVersion is the current dataGhost version.
const AppVersion = "v2.5"

// ── colors ───────────────────────────────────────────────────────────────────

// ColorMode controls when ANSI colors are emitted.
type ColorMode int

const (
	// ColorAuto enables colors only on interactive terminals (honoring NO_COLOR and TERM=dumb).
	ColorAuto ColorMode = iota
	// ColorAlways forces colors on, even when piped.
	ColorAlways
	// ColorNever forces colors off.
	ColorNever
)

// ParseColorMode parses a --color flag value.
func ParseColorMode(s string) (ColorMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "":
		return ColorAuto, nil
	case "always":
		return ColorAlways, nil
	case "never":
		return ColorNever, nil
	default:
		return ColorAuto, fmt.Errorf("invalid color mode %q: must be auto, always, or never", s)
	}
}

// Color codes for terminal output -- populated by Configure.
var (
	ColorReset   = ""
	ColorRed     = ""
	ColorGreen   = ""
	ColorYellow  = ""
	ColorBlue    = ""
	ColorMagenta = ""
	ColorCyan    = ""
	ColorGray    = ""
)

// StdoutIsTTY reports whether stdout is an interactive terminal.
var StdoutIsTTY = false

// Glyphs holds the active drawing character set (Unicode or ASCII fallback).
var Glyphs = unicodeGlyphs

type glyphSet struct {
	BarFilled string
	BarEmpty  string
	BoxTL     string
	BoxTR     string
	BoxBL     string
	BoxBR     string
	BoxH      string
	BoxV      string
	BoxJoinL  string
	BoxJoinR  string
	Check     string
	Spinner   []string
}

var unicodeGlyphs = glyphSet{
	BarFilled: "▓", BarEmpty: "░",
	BoxTL: "╔", BoxTR: "╗", BoxBL: "╚", BoxBR: "╝",
	BoxH: "═", BoxV: "║", BoxJoinL: "╠", BoxJoinR: "╣",
	Check:   "✓",
	Spinner: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
}

var asciiGlyphs = glyphSet{
	BarFilled: "#", BarEmpty: "-",
	BoxTL: "+", BoxTR: "+", BoxBL: "+", BoxBR: "+",
	BoxH: "-", BoxV: "|", BoxJoinL: "+", BoxJoinR: "+",
	Check:   "OK",
	Spinner: []string{"-", "\\", "|", "/"},
}

// Configure resolves the color mode and glyph set from the flag value,
// environment (NO_COLOR, TERM), and terminal capabilities. Call once at startup.
func Configure(mode ColorMode) {
	StdoutIsTTY = term.IsTerminal(int(os.Stdout.Fd()))

	color := false
	switch mode {
	case ColorAlways:
		color = true
	case ColorNever:
		color = false
	default:
		_, noColor := os.LookupEnv("NO_COLOR")
		dumb := os.Getenv("TERM") == "dumb"
		color = StdoutIsTTY && !noColor && !dumb
	}
	if color {
		enableANSI() // no-op on unix; enables VT processing on Windows
	}
	setColors(color)
	Glyphs = pickGlyphs()
}

func setColors(enabled bool) {
	if !enabled {
		ColorReset, ColorRed, ColorGreen, ColorYellow = "", "", "", ""
		ColorBlue, ColorMagenta, ColorCyan, ColorGray = "", "", "", ""
		return
	}
	ColorReset = "\033[0m"
	ColorRed = "\033[31m"
	ColorGreen = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan = "\033[36m"
	ColorGray = "\033[90m"
}

func pickGlyphs() glyphSet {
	if os.Getenv("TERM") == "dumb" {
		return asciiGlyphs
	}
	if runtime.GOOS != "windows" {
		locale := os.Getenv("LC_ALL") + os.Getenv("LC_CTYPE") + os.Getenv("LANG")
		if locale != "" && !strings.Contains(strings.ToLower(locale), "utf") {
			return asciiGlyphs
		}
	}
	return unicodeGlyphs
}

// InitColors is retained for compatibility; equivalent to Configure(ColorAuto).
func InitColors() { Configure(ColorAuto) }

// IsStdinInteractive returns true if stdin is a terminal device.
func IsStdinInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// ── log tags ─────────────────────────────────────────────────────────────────
//
// Color language (keep consistent everywhere):
//
//	red     corruption, destructive actions, errors
//	green   success and positive outcomes
//	yellow  caution: skips, warnings, dry-run, interruptions
//	blue    state changes and informational headers
//	cyan    progress / process milestones, hints
//	gray    noise (unchanged files)
//
// Verbosity levels: LevelAlways prints by default, LevelVerbose needs -v,
// LevelDebug needs -vv.

const (
	LevelAlways  = 0
	LevelVerbose = 1
	LevelDebug   = 2
)

// Color identifies one of the semantic colors at render time.
type Color int

const (
	CNone Color = -1
	CRed  Color = iota
	CGreen
	CYellow
	CBlue
	CMagenta
	CCyan
	CGray
)

// Code returns the active ANSI code (or "" when colors are disabled).
func (c Color) Code() string {
	switch c {
	case CRed:
		return ColorRed
	case CGreen:
		return ColorGreen
	case CYellow:
		return ColorYellow
	case CBlue:
		return ColorBlue
	case CMagenta:
		return ColorMagenta
	case CCyan:
		return ColorCyan
	case CGray:
		return ColorGray
	}
	return ""
}

// TagSpec describes a log tag: its label, semantic color, and minimum verbosity.
type TagSpec struct {
	Name  string
	Color Color
	Level int
}

// tagWidth aligns all tags to the longest label ("HASH MISMATCH").
const tagWidth = 13

// String renders the tag padded to a uniform column width.
func (t TagSpec) String() string {
	label := "[" + t.Name + "]"
	if pad := tagWidth + 2 - runewidth.StringWidth(label); pad > 0 {
		label += strings.Repeat(" ", pad)
	}
	if code := t.Color.Code(); code != "" {
		return code + label + ColorReset
	}
	return label
}

// The tag registry. Use these instead of ad-hoc strings.
var (
	TagOK           = TagSpec{"OK", CGreen, LevelVerbose}
	TagAdded        = TagSpec{"ADDED", CGreen, LevelAlways}
	TagCreated      = TagSpec{"CREATED", CGreen, LevelAlways}
	TagUpdated      = TagSpec{"UPDATED", CBlue, LevelAlways}
	TagCorrupted    = TagSpec{"CORRUPTED", CRed, LevelAlways}
	TagDeleted      = TagSpec{"DELETED", CRed, LevelAlways}
	TagError        = TagSpec{"ERROR", CRed, LevelAlways}
	TagFatal        = TagSpec{"FATAL", CRed, LevelAlways}
	TagHashMismatch = TagSpec{"HASH MISMATCH", CRed, LevelAlways}
	TagWarning      = TagSpec{"WARNING", CYellow, LevelAlways}
	TagMissing      = TagSpec{"MISSING", CYellow, LevelAlways}
	TagNotTracked   = TagSpec{"NOT TRACKED", CYellow, LevelAlways}
	TagNotFound     = TagSpec{"NOT FOUND", CYellow, LevelAlways}
	TagCancelled    = TagSpec{"CANCELLED", CYellow, LevelAlways}
	TagDryRun       = TagSpec{"DRY-RUN", CYellow, LevelAlways}
	TagInterrupted  = TagSpec{"INTERRUPTED", CYellow, LevelAlways}
	TagSkip         = TagSpec{"SKIP", CYellow, LevelDebug}
	TagSkipDir      = TagSpec{"SKIP DIR", CYellow, LevelDebug}
	TagIgnore       = TagSpec{"IGNORE", CYellow, LevelDebug}
	TagUnchanged    = TagSpec{"UNCHANGED", CGray, LevelDebug}
	TagRefresh      = TagSpec{"REFRESH", CGray, LevelDebug}
	TagProcessing   = TagSpec{"PROCESSING", CCyan, LevelAlways}
	TagCompleted    = TagSpec{"COMPLETED", CGreen, LevelAlways}
	TagCleaning     = TagSpec{"CLEANING", CCyan, LevelAlways}
	TagCleaned      = TagSpec{"CLEANED", CGreen, LevelAlways}
	TagUpdating     = TagSpec{"UPDATING", CCyan, LevelAlways}
	TagInfo         = TagSpec{"INFO", CCyan, LevelAlways}
	TagHint         = TagSpec{"HINT", CCyan, LevelAlways}
	TagDir          = TagSpec{"DIR", CCyan, LevelVerbose}
	TagGhost        = TagSpec{"GHOST", CBlue, LevelAlways}
)

// ── width-aware text helpers ─────────────────────────────────────────────────

// Width returns the display width of s in terminal columns (CJK/emoji safe).
func Width(s string) int {
	return runewidth.StringWidth(s)
}

// Pad right-pads s with spaces to display width w (CJK/emoji safe).
func Pad(s string, w int) string {
	if pad := w - runewidth.StringWidth(s); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// Truncate shortens s to display width w, appending an ellipsis when truncated.
func Truncate(s string, w int) string {
	if runewidth.StringWidth(s) <= w {
		return s
	}
	return runewidth.Truncate(s, w, "…")
}

// TruncateLeft shortens s to display width w, keeping the tail and prefixing
// an ellipsis when truncated. Useful for file paths, where the end is unique.
func TruncateLeft(s string, w int) string {
	if runewidth.StringWidth(s) <= w {
		return s
	}
	if w <= 1 {
		return runewidth.Truncate(s, w, "")
	}
	return "…" + runewidth.TruncateLeft(s, w-1, "")
}

// HumanBytes renders a byte count in IEC units (e.g. "1.2 GiB").
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit && exp < 4; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// HumanRate renders bytes/elapsed as a throughput string (e.g. "12.3 MiB/s").
func HumanRate(bytes int64, elapsed time.Duration) string {
	if elapsed <= 0 {
		return ""
	}
	return HumanBytes(int64(float64(bytes)/elapsed.Seconds())) + "/s"
}

// ── progress ─────────────────────────────────────────────────────────────────

// TermWidth returns the terminal width in columns, defaulting to 80.
func TermWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// ProgressState is a snapshot of an in-flight operation for rendering.
type ProgressState struct {
	Op          string
	Current     int64
	Total       int64 // 0 = unknown
	BytesPerSec float64
	Elapsed     time.Duration
	File        string // current file basename, may be ""
}

// RenderProgress renders a single-line progress display adapted to the
// terminal width. It never exceeds TermWidth columns.
func RenderProgress(s ProgressState) string {
	tw := TermWidth()
	prefix := "[" + s.Op + "] "

	rate := ""
	if s.BytesPerSec >= 1024 {
		rate = " " + HumanBytes(int64(s.BytesPerSec)) + "/s"
	}

	if s.Total > 0 {
		pct := float64(s.Current) / float64(s.Total)
		if pct > 1 {
			pct = 1
		}
		counts := fmt.Sprintf(" %3.0f%% (%d/%d)", pct*100, s.Current, s.Total)
		eta := ""
		if s.Current > 0 && s.Current < s.Total && s.Elapsed > 0 {
			rate := float64(s.Current) / s.Elapsed.Seconds()
			if rate > 0 {
				remaining := time.Duration(float64(s.Total-s.Current)/rate) * time.Second
				eta = " ETA " + remaining.Round(time.Second).String()
			}
		}
		file := ""
		if s.File != "" {
			file = " " + s.File
		}
		// Budget: prefix + counts + rate + eta + file; the bar takes the rest.
		fixed := runewidth.StringWidth(prefix) + runewidth.StringWidth(counts) +
			runewidth.StringWidth(rate) + runewidth.StringWidth(eta) + runewidth.StringWidth(file)
		barW := min(max(tw-fixed-1, 10), 50)
		filled := int(float64(barW) * pct)
		bar := strings.Repeat(Glyphs.BarFilled, filled) + strings.Repeat(Glyphs.BarEmpty, barW-filled)
		line := prefix + bar + counts + rate + eta + file
		return fitWidth(line, tw)
	}

	// Unknown total: spinner-style counter.
	counts := fmt.Sprintf(" %d files", s.Current)
	file := ""
	if s.File != "" {
		file = " " + s.File
	}
	line := prefix + Glyphs.BarFilled + counts + rate + file
	return fitWidth(line, tw)
}

// fitWidth truncates a rendered line (which may contain ANSI codes) to the
// terminal width, truncating only the trailing plain-text portion.
func fitWidth(line string, tw int) string {
	// ANSI codes carry no display width; StringWidth miscounts them. RenderProgress
	// only appends color-free content after the bar, so a rune-count trim of the
	// tail is sufficient when we exceed the width.
	if runewidth.StringWidth(stripANSI(line)) <= tw {
		return line
	}
	return runewidth.Truncate(stripANSI(line), tw, "")
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Spinner renders an indeterminate activity indicator for long single operations.
type Spinner struct {
	mu     *sync.Mutex
	msg    string
	done   chan struct{}
	wg     sync.WaitGroup
	active bool
}

// NewSpinner creates a spinner that renders msg next to an animated glyph.
// The provided mutex must be the app's output lock so frames interleave
// safely with log lines.
func NewSpinner(mu *sync.Mutex, msg string) *Spinner {
	return &Spinner{mu: mu, msg: msg, done: make(chan struct{})}
}

// Start begins rendering frames until Stop is called.
func (s *Spinner) Start() {
	s.active = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		i := 0
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				s.mu.Lock()
				frame := Glyphs.Spinner[i%len(Glyphs.Spinner)]
				fmt.Printf("\r\033[K%s %s", ColorCyan+frame+ColorReset, s.msg)
				s.mu.Unlock()
				i++
			}
		}
	}()
}

// Stop halts the spinner and clears its line.
func (s *Spinner) Stop() {
	if !s.active {
		return
	}
	close(s.done)
	s.wg.Wait()
	s.mu.Lock()
	fmt.Print("\r\033[K")
	s.mu.Unlock()
}

// ── command suggestions ──────────────────────────────────────────────────────

// Levenshtein returns the edit distance between a and b (case-insensitive).
func Levenshtein(a, b string) int {
	a, b = strings.ToLower(a), strings.ToLower(b)
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur := make([]int, len(br)+1)
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(br)]
}

// SuggestCommand returns the closest command to input, or "" if none are close
// enough to be a plausible typo.
func SuggestCommand(input string, commands []string) string {
	best, bestDist := "", 1<<30
	for _, c := range commands {
		if d := Levenshtein(input, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	maxDist := 2
	if len(input) < 3 {
		maxDist = 1
	}
	if bestDist <= maxDist {
		return best
	}
	return ""
}

// ── boxes & help ─────────────────────────────────────────────────────────────

// BoxLine returns a single bordered line with text centered in w inner columns.
func BoxLine(w int, text string) string {
	pad := w - runewidth.StringWidth(text)
	if pad < 0 {
		pad = 0
	}
	lp, rp := pad/2, pad-pad/2
	return ColorBlue + Glyphs.BoxV + ColorReset + strings.Repeat(" ", lp) + text +
		strings.Repeat(" ", rp) + ColorBlue + Glyphs.BoxV + ColorReset + "\n"
}

// Help prints the usage banner and command reference.
func Help() {
	const w = 58 // inner width of the help box
	top := ColorBlue + Glyphs.BoxTL + strings.Repeat(Glyphs.BoxH, w) + Glyphs.BoxTR + ColorReset + "\n"
	bot := ColorBlue + Glyphs.BoxBL + strings.Repeat(Glyphs.BoxH, w) + Glyphs.BoxBR + ColorReset + "\n"
	fmt.Print(
		top +
			BoxLine(w, "dataGhost "+AppVersion) +
			BoxLine(w, "File Integrity Tracking Utility") +
			bot + "\n" +
			ColorYellow + "USAGE:" + ColorReset + "\n" +
			"  dataGhost [OPTIONS] COMMAND " + ColorGray + "[PATH]" + ColorReset + "\n\n" +
			ColorYellow + "COMMANDS:" + ColorReset + "\n" +
			"  " + ColorGreen + "add" + ColorReset + "       Add files to tracking\n" +
			"  " + ColorRed + "del" + ColorReset + "       Remove files from tracking\n" +
			"  " + ColorCyan + "check" + ColorReset + "     Verify file integrity\n" +
			"  " + ColorYellow + "clean" + ColorReset + "     Remove missing file entries from tracking\n" +
			"  " + ColorMagenta + "update" + ColorReset + "    Update old .ghost files with size/modification metadata\n" +
			"  " + ColorBlue + "list" + ColorReset + "      List tracked files from .ghost file(s)\n" +
			"  " + ColorBlue + "init" + ColorReset + "      Create a commented .ghostconf template\n" +
			"  " + ColorBlue + "version" + ColorReset + "   Print version information\n" +
			"  " + ColorBlue + "help" + ColorReset + "      Show this help\n" +
			"  " + ColorBlue + "completion" + ColorReset + "  Print a shell completion script\n\n" +
			ColorYellow + "OPTIONS:" + ColorReset + "\n" +
			"  " + ColorCyan + "-r" + ColorReset + "              Process directories recursively\n" +
			"  " + ColorCyan + "-p" + ColorReset + " N            Set number of parallel workers (default: CPU count)\n" +
			"  " + ColorCyan + "-f" + ColorReset + "              Force operations without prompts\n" +
			"  " + ColorCyan + "-d" + ColorReset + "              Dry run: show what would happen without writing\n" +
			"  " + ColorCyan + "-qc" + ColorReset + "             Quick check: skip rehash if size/modtime unchanged\n" +
			"  " + ColorCyan + "-q" + ColorReset + "              Quiet mode (prints a one-line summary)\n" +
			"  " + ColorCyan + "-v" + ColorReset + "              Verbose output (repeatable: -v -v or -vv)\n" +
			"  " + ColorCyan + "--json" + ColorReset + "          Output results as JSON lines\n" +
			"  " + ColorCyan + "--color" + ColorReset + " MODE    Color output: auto, always, never\n" +
			"  " + ColorCyan + "-b" + ColorReset + "              Raw byte sizes in list output\n" +
			"  " + ColorCyan + "-i" + ColorReset + " PATTERN      Ignore pattern (can be used multiple times)\n" +
			"  " + ColorCyan + "-c" + ColorReset + "              Load .ghostconf from target directory\n" +
			"  " + ColorCyan + "-cf" + ColorReset + " " + ColorGray + "FILE" + ColorReset + "        Load config from a specific file\n" +
			"  " + ColorCyan + "-cs" + ColorReset + "             Strict mode (no local overrides)\n" +
			"  " + ColorCyan + "-csf" + ColorReset + " " + ColorGray + "FILE" + ColorReset + "       Load config from file (strict mode)\n\n" +
			ColorYellow + "CONFIG FILE EXAMPLE " + ColorGray + "(.ghostconf)" + ColorReset + ":\n" +
			"  " + ColorCyan + "ignore" + ColorReset + ":\n" +
			"    - " + ColorGreen + "\"*.tmp\"" + ColorReset + "\n" +
			"    - " + ColorGreen + "\"*.log\"" + ColorReset + "\n" +
			"    - " + ColorGreen + "\"node_modules/\"" + ColorReset + "\n" +
			"    - " + ColorGreen + "\".git/\"" + ColorReset + "\n" +
			"  " + ColorCyan + "buffer" + ColorReset + ": " + ColorGreen + "262144" + ColorReset + "\n" +
			"  " + ColorCyan + "parallel" + ColorReset + ": " + ColorGreen + "4" + ColorReset + "\n" +
			"  " + ColorCyan + "show_progress" + ColorReset + ": " + ColorGreen + "true" + ColorReset + "\n\n" +
			ColorYellow + "EXIT CODES:" + ColorReset + "\n" +
			"  0  Success\n" +
			"  1  Corruption detected / unexpected changes / missing files\n" +
			"  2  Error occurred\n",
	)
}
