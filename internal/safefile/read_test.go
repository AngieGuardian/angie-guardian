package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnforcesLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 4); err == nil {
		t.Fatal("Read accepted an oversized file")
	}
	got, err := Read(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "12345" {
		t.Fatalf("Read = %q", got)
	}
}
