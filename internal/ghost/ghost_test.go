package ghost

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeFileInfo struct {
	size    int64
	modTime time.Time
}

func (f *fakeFileInfo) Name() string       { return "fake" }
func (f *fakeFileInfo) Size() int64        { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode  { return 0644 }
func (f *fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f *fakeFileInfo) IsDir() bool        { return false }
func (f *fakeFileInfo) Sys() interface{}   { return nil }

func TestReadWriteGhostRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	ghostPath := filepath.Join(tmpDir, ".ghost")

	original := map[string]FileData{
		"file1.txt": {
			Blake2b:  "a1b2c3d4e5f6",
			Size:     12345,
			Modified: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		},
		"file2.bin": {
			Blake2b: "deadbeef",
			Size:    0,
		},
	}

	if err := WriteGhost(original, ghostPath); err != nil {
		t.Fatalf("WriteGhost error: %v", err)
	}

	readBack, err := ReadGhost(ghostPath)
	if err != nil {
		t.Fatalf("ReadGhost error: %v", err)
	}

	if len(readBack) != len(original) {
		t.Fatalf("readBack len = %d, want %d", len(readBack), len(original))
	}

	for name, orig := range original {
		got, ok := readBack[name]
		if !ok {
			t.Errorf("missing entry %q", name)
			continue
		}
		if got.Blake2b != orig.Blake2b {
			t.Errorf("%q Blake2b = %q, want %q", name, got.Blake2b, orig.Blake2b)
		}
		if got.Size != orig.Size {
			t.Errorf("%q Size = %d, want %d", name, got.Size, orig.Size)
		}
		if !orig.Modified.IsZero() && !got.Modified.Equal(orig.Modified) {
			t.Errorf("%q Modified = %v, want %v", name, got.Modified, orig.Modified)
		}
	}
}

func TestReadGhostMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	ghostPath := filepath.Join(tmpDir, "nonexistent.ghost")

	data, err := ReadGhost(ghostPath)
	if err != nil {
		t.Fatalf("ReadGhost error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty map, got %d entries", len(data))
	}
}

func TestReadGhostEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	ghostPath := filepath.Join(tmpDir, ".ghost")

	if err := os.WriteFile(ghostPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	data, err := ReadGhost(ghostPath)
	if err != nil {
		t.Fatalf("ReadGhost error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty map, got %d entries", len(data))
	}
}

func TestNeedsRehash(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		size    int64
		modTime time.Time
		stored  FileData
		want    bool
	}{
		{
			name:    "identical",
			size:    100,
			modTime: now,
			stored:  FileData{Size: 100, Modified: now},
			want:    false,
		},
		{
			name:    "size changed",
			size:    200,
			modTime: now,
			stored:  FileData{Size: 100, Modified: now},
			want:    true,
		},
		{
			name:    "modtime changed",
			size:    100,
			modTime: now.Add(time.Second),
			stored:  FileData{Size: 100, Modified: now},
			want:    true,
		},
		{
			name:    "no stored size",
			size:    100,
			modTime: now,
			stored:  FileData{Size: 0, Modified: now},
			want:    true,
		},
		{
			name:    "no stored modtime",
			size:    100,
			modTime: now,
			stored:  FileData{Size: 100, Modified: time.Time{}},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := &fakeFileInfo{size: tt.size, modTime: tt.modTime}
			got := NeedsRehash(fi, tt.stored)
			if got != tt.want {
				t.Errorf("NeedsRehash() = %v, want %v", got, tt.want)
			}
		})
	}
}
