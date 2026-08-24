//go:build !windows

// Copyright (c) 2026 apetl.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package output

// enableANSI is a no-op on unix-like systems, where terminals handle ANSI
// escape sequences natively.
func enableANSI() {}
