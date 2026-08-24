package hash

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestCalcHash(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		wantHash string
	}{
		{
			name:     "empty file",
			content:  "",
			wantHash: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			name:     "hello world",
			content:  "hello world",
			wantHash: "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
		},
		{
			name:     "multiline content",
			content:  "line1\nline2\nline3\n",
			wantHash: "",
		},
	}

	h, _ := blake2b.New256(nil)
	h.Write([]byte("line1\nline2\nline3\n"))
	tests[2].wantHash = fmt.Sprintf("%x", h.Sum(nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, tt.name+".txt")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("write file: %v", err)
			}

			got, err := CalcHash(path, 0)
			if err != nil {
				t.Fatalf("CalcHash error: %v", err)
			}
			if got != tt.wantHash {
				t.Errorf("CalcHash() = %s, want %s", got, tt.wantHash)
			}
		})
	}
}

func TestCalcHashMmap(t *testing.T) {
	// A file above the mmap threshold exercises the memory-mapped path,
	// which swaps in golang.org/x/exp/mmap and routes through HashPool.
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "big.bin")
	size := MmapThreshold + 1*1024*1024 // 11 MiB -> mmap path
	chunk := []byte("0123456789ABCDEF")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	hExp, _ := blake2b.New256(nil)
	buf := make([]byte, 64*1024)
	for i := int64(0); i < int64(size); i += int64(len(buf)) {
		n := int64(len(buf))
		if i+n > int64(size) {
			n = int64(size) - i
		}
		for j := int64(0); j < n; j += int64(len(chunk)) {
			c := int64(len(chunk))
			if j+c > n {
				c = n - j
			}
			f.Write(chunk[:c])
			hExp.Write(chunk[:c])
		}
	}
	f.Close()
	want := fmt.Sprintf("%x", hExp.Sum(nil))

	got, err := CalcHash(path, 0)
	if err != nil {
		t.Fatalf("CalcHash error: %v", err)
	}
	if got != want {
		t.Errorf("mmap path hash mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestCalcHashSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.txt")
	link := filepath.Join(tmpDir, "link.txt")

	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	_, err := CalcHash(link, 0)
	if err == nil {
		t.Error("expected error for symlink, got nil")
	}
}

func TestGetBufferSize(t *testing.T) {
	tests := []struct {
		name      string
		fileSize  int64
		cfgBuffer int
		want      int
	}{
		{
			name:      "user override",
			fileSize:  1024,
			cfgBuffer: 4096,
			want:      4096,
		},
		{
			name:      "small file",
			fileSize:  512 * 1024,
			cfgBuffer: 0,
			want:      MinBuffer,
		},
		{
			name:      "medium file",
			fileSize:  50 * 1024 * 1024,
			cfgBuffer: 0,
			want:      DefaultBuffer,
		},
		{
			name:      "large file",
			fileSize:  500 * 1024 * 1024,
			cfgBuffer: 0,
			want:      MaxBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetBufferSize(tt.fileSize, tt.cfgBuffer)
			if got != tt.want {
				t.Errorf("GetBufferSize() = %d, want %d", got, tt.want)
			}
		})
	}
}
