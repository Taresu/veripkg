// Package sumsfile parses SHA256SUMS-format files.
//
// The format, as produced by sha256sum(1), is one entry per line:
//
//	<64-hex-digest><space><space-or-'*'><filename>
//
// The single space separates text mode; '*' marks binary mode. Leading
// "./" on filenames and surrounding whitespace are tolerated. Blank lines
// and lines beginning with '#' are ignored.
package sumsfile

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Sums maps a filename to its lowercase hex SHA-256 digest.
type Sums map[string]string

// Parse reads a SHA256SUMS-format stream. It returns an error if a
// non-blank, non-comment line is malformed, so a corrupt sums file is a
// hard failure rather than a silent partial match.
func Parse(r io.Reader) (Sums, error) {
	out := Sums{}
	sc := bufio.NewScanner(r)
	// Sums files are tiny, but a generous buffer avoids surprises.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		// Split into digest and the remainder (the filename field).
		fields := strings.SplitN(raw, " ", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: malformed entry %q", line, raw)
		}
		digest := strings.ToLower(strings.TrimSpace(fields[0]))
		if !isHex64(digest) {
			return nil, fmt.Errorf("line %d: invalid sha256 digest %q", line, fields[0])
		}

		name := strings.TrimSpace(fields[1])
		name = strings.TrimPrefix(name, "*") // binary-mode marker
		name = strings.TrimSpace(name)
		name = strings.TrimPrefix(name, "./")
		if name == "" {
			return nil, fmt.Errorf("line %d: empty filename", line)
		}
		out[name] = digest
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no entries found")
	}
	return out, nil
}

// Lookup returns the expected digest for name. It matches on the exact name
// and, as a fallback, on the base name, since callers often pass a local
// path whose directory differs from the sums file's recorded name.
func (s Sums) Lookup(name string) (string, bool) {
	if d, ok := s[name]; ok {
		return d, true
	}
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		if d, ok := s[name[i+1:]]; ok {
			return d, true
		}
	}
	return "", false
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
