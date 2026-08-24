//go:build windows

package output

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableANSI turns on virtual terminal processing for the stdout console so
// ANSI escape sequences work on legacy cmd.exe/conhost. It is a no-op when
// stdout is not a console or the call fails (colors will simply be disabled
// by the TTY check in that case).
func enableANSI() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	const enableVirtualTerminalProcessing = 0x0004
	if mode&enableVirtualTerminalProcessing != 0 {
		return
	}
	_ = windows.SetConsoleMode(h, mode|enableVirtualTerminalProcessing)
}
