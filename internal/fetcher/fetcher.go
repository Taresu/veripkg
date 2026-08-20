// Package fetcher retrieves bytes for a reference that is either a local path,
// a file:// URL, or an https:// URL. It is pure I/O with sane limits; it makes
// no trust decisions.
package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxBytes caps any single fetch. Sums files, signatures and keys are tiny;
// this guards against a hostile endpoint streaming forever. Local files (the
// artifact being verified) are read via ReadFileCapped with a larger cap.
const MaxBytes = 32 << 20 // 32 MiB

// DefaultTimeout bounds network fetches.
const DefaultTimeout = 30 * time.Second

// Fetch returns the contents of ref. Plain paths and file:// URLs read from
// disk; http/https are downloaded with a timeout and size cap. Intended for
// small control files (sums, signatures, keys).
func Fetch(ctx context.Context, ref string) ([]byte, error) {
	switch scheme(ref) {
	case "http", "https":
		return fetchHTTP(ctx, ref)
	case "file":
		u, err := url.Parse(ref)
		if err != nil {
			return nil, err
		}
		return readFile(u.Path, MaxBytes)
	default: // treat as a local path
		return readFile(ref, MaxBytes)
	}
}

// LocalPath resolves ref to a local filesystem path when it denotes one
// (plain path or file:// URL), reporting false for remote references. Used for
// the artifact being verified, which must exist locally.
func LocalPath(ref string) (string, bool) {
	switch scheme(ref) {
	case "file":
		if u, err := url.Parse(ref); err == nil {
			return u.Path, true
		}
		return "", false
	case "http", "https":
		return "", false
	default:
		return ref, true
	}
}

func fetchHTTP(ctx context.Context, ref string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", ref, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: http %d", ref, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("fetching %s: response exceeds %d bytes", ref, MaxBytes)
	}
	return data, nil
}

func readFile(path string, max int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", filepath.Base(path), max)
	}
	return os.ReadFile(path)
}

func scheme(ref string) string {
	i := strings.Index(ref, "://")
	if i <= 0 {
		return ""
	}
	return strings.ToLower(ref[:i])
}
