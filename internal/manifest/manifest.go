// Package manifest persists verified pins so they can be re-checked idempotently
// (e.g. in CI). It uses stdlib JSON rather than a third-party TOML parser: for a
// security tool, keeping the dependency/supply-chain surface small is worth more
// than the marginal ergonomics of TOML. The on-disk file is veripkg.json.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// DefaultName is the conventional manifest filename in a project directory.
const DefaultName = "veripkg.json"

// Entry records how to re-verify a single pinned artifact.
type Entry struct {
	Name           string `json:"name"`
	File           string `json:"file"`
	Hash           string `json:"hash,omitempty"`
	SumsURL        string `json:"sums_url,omitempty"`
	SigURL         string `json:"sig_url,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	Tier           string `json:"tier"` // tier achieved when pinned, for reference
}

// Manifest is an ordered-by-name set of pinned entries.
type Manifest struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Load reads a manifest. A missing file yields an empty manifest, not an error,
// so `pin` can create the first entry.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Manifest{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if m.Version == 0 {
		m.Version = 1
	}
	return &m, nil
}

// Save writes the manifest, entries sorted by name for stable diffs.
func Save(path string, m *Manifest) error {
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// Upsert replaces any entry with the same name, else appends.
func (m *Manifest) Upsert(e Entry) {
	for i := range m.Entries {
		if m.Entries[i].Name == e.Name {
			m.Entries[i] = e
			return
		}
	}
	m.Entries = append(m.Entries, e)
}
