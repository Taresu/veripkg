package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchLocalPathAndFileURL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sums")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{p, "file://" + p} {
		got, err := Fetch(context.Background(), ref)
		if err != nil {
			t.Fatalf("Fetch(%q): %v", ref, err)
		}
		if string(got) != "hello" {
			t.Fatalf("Fetch(%q) = %q", ref, got)
		}
	}
}

func TestFetchHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("remote-sums"))
	}))
	defer srv.Close()

	got, err := Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "remote-sums" {
		t.Fatalf("got %q", got)
	}
}

func TestFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error on 404")
	}
}

func TestLocalPath(t *testing.T) {
	if p, ok := LocalPath("/tmp/x"); !ok || p != "/tmp/x" {
		t.Errorf("plain path: %q,%v", p, ok)
	}
	if p, ok := LocalPath("file:///tmp/x"); !ok || p != "/tmp/x" {
		t.Errorf("file url: %q,%v", p, ok)
	}
	if _, ok := LocalPath("https://example.com/x"); ok {
		t.Error("https should not be a local path")
	}
}
