package hasher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSHA256Bytes(t *testing.T) {
	// Known vector: SHA-256 of the empty string.
	got := SHA256Bytes(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("SHA256Bytes(nil) = %q, want %q", got, want)
	}

	// SHA-256 of "abc".
	got = SHA256Bytes([]byte("abc"))
	want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("SHA256Bytes(abc) = %q, want %q", got, want)
	}
}

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("SHA256File = %q, want %q", got, want)
	}
}

func TestSHA256FileMissing(t *testing.T) {
	if _, err := SHA256File(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
