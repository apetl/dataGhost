// Package output provides terminal formatting, colors, progress bars, and help text.
package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// AppVersion is the current dataGhost version.
const AppVersion = "v2.4"

// Color codes for terminal output -- only emitted when stdout is a TTY.
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

// InitColors populates color variables when stdout is a terminal device.
func InitColors() {
	fi, err := os.Stdout.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		ColorReset = "\033[0m"
		ColorRed = "\033[31m"
		ColorGreen = "\033[32m"
		ColorYellow = "\033[33m"
		ColorBlue = "\033[34m"
		ColorMagenta = "\033[35m"
		ColorCyan = "\033[36m"
		ColorGray = "\033[90m"
	}
}

// IsStdinInteractive returns true if stdin is a terminal device.
func IsStdinInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ProgressBar renders a visual progress bar with percentage.
type ProgressBar struct {
	mu        sync.Mutex
	width     int
	operation string
}

// NewProgressBar creates a progress bar with the given display width.
func NewProgressBar(width int) *ProgressBar {
	if width < 10 {
		width = 40
	}
	return &ProgressBar{width: width}
}

// Render returns the progress bar string for current/total.
func (pb *ProgressBar) Render(current, total int64, operation string) string {
	if total <= 0 {
		return fmt.Sprintf("%s[%s] Processing items: %d%s", ColorCyan, operation, current, ColorReset)
	}
	pct := float64(current) / float64(total) * 100
	filled := int(float64(pb.width) * float64(current) / float64(total))
	if filled > pb.width {
		filled = pb.width
	}
	bar := strings.Repeat("▓", filled) + strings.Repeat("░", pb.width-filled)
	return fmt.Sprintf("%s[%s] %s %3.0f%% (%d/%d)%s", ColorCyan, operation, bar, pct, current, total, ColorReset)
}

// AtomicProgress wraps a ProgressBar with thread-safe current/total tracking.
type AtomicProgress struct {
	pb      *ProgressBar
	current atomic.Int64
	total   int64
	op      string
}

// NewAtomicProgress creates a thread-safe progress tracker.
func NewAtomicProgress(total int64, operation string) *AtomicProgress {
	return &AtomicProgress{
		pb:    NewProgressBar(40),
		total: total,
		op:    operation,
	}
}

// Inc increments the progress counter and returns the rendered bar.
func (ap *AtomicProgress) Inc() string {
	cur := ap.current.Add(1)
	return ap.pb.Render(cur, ap.total, ap.op)
}

// Current returns the current progress count.
func (ap *AtomicProgress) Current() int64 {
	return ap.current.Load()
}

// BoxLine returns a single bordered line padded to exactly w inner characters.
func BoxLine(w int, text string) string {
	pad := w - len(text)
	if pad < 0 {
		pad = 0
	}
	lp := pad / 2
	rp := pad - lp
	return ColorBlue + "║" + ColorReset + strings.Repeat(" ", lp) + text + strings.Repeat(" ", rp) + ColorBlue + "║" + ColorReset + "\n"
}

// Help prints the usage banner and command reference.
func Help() {
	const w = 58 // inner width of the help box
	top := ColorBlue + "╔" + strings.Repeat("═", w) + "╗" + ColorReset + "\n"
	bot := ColorBlue + "╚" + strings.Repeat("═", w) + "╝" + ColorReset + "\n"
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
			"  " + ColorBlue + "version" + ColorReset + "   Print version information\n\n" +
			ColorYellow + "OPTIONS:" + ColorReset + "\n" +
			"  " + ColorCyan + "-r" + ColorReset + "              Process directories recursively\n" +
			"  " + ColorCyan + "-p" + ColorReset + " N            Set number of parallel workers (default: CPU count)\n" +
			"  " + ColorCyan + "-f" + ColorReset + "              Force operations without prompts\n" +
			"  " + ColorCyan + "-d" + ColorReset + "              Dry run: show what would happen without writing\n" +
			"  " + ColorCyan + "-qc" + ColorReset + "             Quick check: skip rehash if size/modtime unchanged\n" +
			"  " + ColorCyan + "-q" + ColorReset + "              Quiet mode\n" +
			"  " + ColorCyan + "--json" + ColorReset + "          Output results as JSON lines\n" +
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
			"  1  Corruption detected / unexpected changes\n" +
			"  2  Error occurred\n",
	)
}
