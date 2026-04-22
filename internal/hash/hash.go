// Package hash provides BLAKE2b hashing with memory-mapped and buffered strategies.
package hash

import (
	"fmt"
	"hash"
	"io"
	"os"
	"sync"

	"github.com/edsrzf/mmap-go"
	"golang.org/x/crypto/blake2b"

	"dataGhost/internal/output"
)

const (
	MinBuffer     = 64 * 1024
	DefaultBuffer = 256 * 1024
	MaxBuffer     = 1024 * 1024
	MmapThreshold = 10 * 1024 * 1024
)

var (
	BufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, DefaultBuffer)
			return &buf
		},
	}
	HashPool = sync.Pool{
		New: func() interface{} {
			h, err := blake2b.New256(nil)
			if err != nil {
				panic(fmt.Sprintf("failed to create blake2b hasher: %v", err))
			}
			return h
		},
	}
)

// GetBufferSize selects a buffer size based on file size and optional user override.
func GetBufferSize(fileSize int64, cfgBuffer int) int {
	if cfgBuffer > 0 {
		return cfgBuffer
	}
	switch {
	case fileSize < 1024*1024:
		return MinBuffer
	case fileSize < 100*1024*1024:
		return DefaultBuffer
	default:
		return MaxBuffer
	}
}

// CalcHashMmap computes the BLAKE2b-256 hash of a file using memory mapping.
func CalcHashMmap(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to mmap file: %w", err)
	}
	defer func() {
		if err := data.Unmap(); err != nil {
			fmt.Fprintf(os.Stderr, "%s[WARNING]%s Failed to unmap '%s': %v\n", output.ColorYellow, output.ColorReset, path, err)
		}
	}()

	h, err := blake2b.New256(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create hasher: %w", err)
	}
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// CalcHash computes the BLAKE2b-256 hash of a file, using mmap for large files
// and buffered streaming for smaller ones.
func CalcHash(path string, cfgBuffer int) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat file '%s': %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("skipping symbolic link: '%s'", path)
	}

	fileSize := st.Size()
	if fileSize > MmapThreshold {
		if hashStr, err := CalcHashMmap(path); err == nil {
			return hashStr, nil
		}
		// fall through to buffered read on mmap failure
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer f.Close()

	h := HashPool.Get().(hash.Hash)
	h.Reset()

	bufPtr := BufferPool.Get().(*[]byte)
	buf := *bufPtr
	bufSize := GetBufferSize(fileSize, cfgBuffer)
	if cap(buf) < bufSize {
		buf = make([]byte, bufSize)
		*bufPtr = buf
	} else {
		buf = buf[:bufSize]
	}

	_, copyErr := io.CopyBuffer(h, f, buf)
	if cap(buf) <= DefaultBuffer {
		BufferPool.Put(bufPtr)
	}
	if copyErr != nil {
		HashPool.Put(h)
		return "", fmt.Errorf("failed to read file '%s': %w", path, copyErr)
	}
	hashStr := fmt.Sprintf("%x", h.Sum(nil))
	HashPool.Put(h)
	return hashStr, nil
}
