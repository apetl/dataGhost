//go:build windows

// Copyright (c) 2026 apetl.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
