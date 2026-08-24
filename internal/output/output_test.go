package output

import (
	"strings"
	"testing"
	"time"
)

func TestParseColorMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want ColorMode
	}{
		{"auto", ColorAuto}, {"", ColorAuto},
		{"always", ColorAlways}, {"ALWAYS", ColorAlways},
		{"never", ColorNever},
	} {
		got, err := ParseColorMode(tc.in)
		if err != nil {
			t.Fatalf("ParseColorMode(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseColorMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, err := ParseColorMode("sometimes"); err == nil {
		t.Error("ParseColorMode(sometimes) should error")
	}
}

func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{5 << 20, "5.0 MiB"},
		{3 << 30, "3.0 GiB"},
		{2 << 40, "2.0 TiB"},
	} {
		if got := HumanBytes(tc.in); got != tc.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanRate(t *testing.T) {
	if got := HumanRate(10<<20, 2*time.Second); got != "5.0 MiB/s" {
		t.Errorf("HumanRate = %q, want %q", got, "5.0 MiB/s")
	}
	if got := HumanRate(100, 0); got != "" {
		t.Errorf("HumanRate with zero duration = %q, want empty", got)
	}
}

func TestPadWidthCJK(t *testing.T) {
	if got := Width("你好"); got != 4 {
		t.Errorf("Width(CJK) = %d, want 4", got)
	}
	if got := Pad("ab", 5); got != "ab   " {
		t.Errorf("Pad ascii = %q", got)
	}
	if got := Pad("你好", 5); got != "你好 " {
		t.Errorf("Pad CJK = %q, want one trailing space", got)
	}
	if got := Pad("toolong", 3); got != "toolong" {
		t.Errorf("Pad should not shrink, got %q", got)
	}
}

func TestTruncateHelpers(t *testing.T) {
	if got := Truncate("hello", 3); got != "he…" {
		t.Errorf("Truncate = %q, want %q", got, "he…")
	}
	if got := Truncate("hi", 5); got != "hi" {
		t.Errorf("Truncate short = %q, want unchanged", got)
	}
	if got := TruncateLeft("abcdef", 4); got != "…def" {
		t.Errorf("TruncateLeft = %q, want %q", got, "…def")
	}
}

func TestTagWidthUniform(t *testing.T) {
	tags := []TagSpec{TagOK, TagAdded, TagCorrupted, TagMissing, TagNotTracked,
		TagHashMismatch, TagError, TagInterrupted, TagProcessing, TagHint}
	for _, tag := range tags {
		if w := Width(tag.String()); w != tagWidth+2 {
			t.Errorf("tag %q width = %d, want %d", tag.Name, w, tagWidth+2)
		}
	}
}

func TestSuggestCommand(t *testing.T) {
	cmds := []string{"add", "check", "del", "list"}
	if got := SuggestCommand("chek", cmds); got != "check" {
		t.Errorf("SuggestCommand(chek) = %q, want check", got)
	}
	if got := SuggestCommand("ad", cmds); got != "add" {
		t.Errorf("SuggestCommand(ad) = %q, want add", got)
	}
	if got := SuggestCommand("xyzzy", cmds); got != "" {
		t.Errorf("SuggestCommand(xyzzy) = %q, want empty", got)
	}
}

func TestRenderProgressFitsWidth(t *testing.T) {
	line := RenderProgress(ProgressState{
		Op: "check", Current: 50, Total: 100,
		BytesPerSec: 12 << 20, Elapsed: 5 * time.Second,
		File: "somefile.txt",
	})
	if w := Width(line); w > TermWidth() {
		t.Errorf("progress line width %d exceeds terminal width %d", w, TermWidth())
	}
	if !strings.Contains(line, "(50/100)") {
		t.Errorf("progress line missing counts: %q", line)
	}

	// Unknown total renders without a bar or percentage.
	ind := RenderProgress(ProgressState{Op: "add", Current: 42, File: "x.bin"})
	if strings.Contains(ind, "%") {
		t.Errorf("indeterminate progress should not show percent: %q", ind)
	}
	if !strings.Contains(ind, "42 files") {
		t.Errorf("indeterminate progress missing count: %q", ind)
	}
}

func TestStripANSI(t *testing.T) {
	if got := stripANSI("\033[31mred\033[0m"); got != "red" {
		t.Errorf("stripANSI = %q, want %q", got, "red")
	}
}

func TestLevenshtein(t *testing.T) {
	if d := Levenshtein("check", "check"); d != 0 {
		t.Errorf("identical distance = %d, want 0", d)
	}
	if d := Levenshtein("CHEK", "check"); d != 1 {
		t.Errorf("case-insensitive distance = %d, want 1", d)
	}
	if d := Levenshtein("", "abc"); d != 3 {
		t.Errorf("empty distance = %d, want 3", d)
	}
}
