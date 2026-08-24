//go:build !windows

package output

// enableANSI is a no-op on unix-like systems, where terminals handle ANSI
// escape sequences natively.
func enableANSI() {}
