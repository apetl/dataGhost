package main

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func BenchmarkSprintf(b *testing.B) {
	data := make([]byte, 32) // BLAKE2b-256 size
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("%x", data)
	}
}

func BenchmarkHexEncodeToString(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		_ = hex.EncodeToString(data)
	}
}
