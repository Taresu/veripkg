// Package keystore persists the set of GPG public keys the user has explicitly
// chosen to trust. Trust is deliberately explicit: a key is usable for signed
// verification only after it has been recorded here, which is what makes the
// TierSigned result meaningful rather than trust-on-first-sight-from-anywhere.
package keystore

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/tsalada/veripkg/internal/pgp"
)

// Store is a directory of trusted public keys, one file per key named by its
// fingerprint.
type Store struct {
	dir string
}

// Open returns a store rooted at dir/keys, creating it if needed.
func Open(dir string) (*Store, error) {
	kdir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(kdir, 0o755); err != nil {
		return nil, fmt.Errorf("creating key store: %w", err)
	}
	return &Store{dir: kdir}, nil
}

// DefaultDir returns the default config directory for veripkg, honoring
// $VERIPKG_CONFIG then $XDG_CONFIG_HOME, falling back to ~/.config/veripkg.
func DefaultDir() string {
	if d := os.Getenv("VERIPKG_CONFIG"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "veripkg")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".veripkg"
	}
	return filepath.Join(home, ".config", "veripkg")
}

// Trust records key material (armored or binary, possibly several keys) as
// trusted and returns the fingerprints added.
func (s *Store) Trust(keyData []byte) ([]string, error) {
	entities, err := pgp.ReadKeys(keyData)
	if err != nil {
		return nil, err
	}
	var added []string
	for _, e := range entities {
		fpr := pgp.Fingerprint(e.PrimaryKey.Fingerprint)
		if err := s.writeEntity(fpr, e); err != nil {
			return nil, err
		}
		added = append(added, fpr)
	}
	if len(added) == 0 {
		return nil, fmt.Errorf("no keys found in input")
	}
	return added, nil
}

func (s *Store) writeEntity(fpr string, e *openpgp.Entity) error {
	path := filepath.Join(s.dir, fpr+".asc")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := armorEncoder(f)
	if err != nil {
		return err
	}
	if err := e.Serialize(w); err != nil {
		return err
	}
	return w.Close()
}

// Keyring loads all trusted keys as a single keyring for signature checking.
func (s *Store) Keyring() (pgp.Keyring, error) {
	files, err := s.list()
	if err != nil {
		return nil, err
	}
	var kr pgp.Keyring
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		el, err := pgp.ReadKeys(data)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", filepath.Base(p), err)
		}
		kr = append(kr, el...)
	}
	return kr, nil
}

// IsTrusted reports whether a key with the given fingerprint is recorded.
func (s *Store) IsTrusted(fpr string) bool {
	fpr = strings.ToUpper(strings.TrimSpace(fpr))
	if fpr == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(s.dir, fpr+".asc"))
	return err == nil
}

// Trusted returns the sorted fingerprints of all trusted keys.
func (s *Store) Trusted() ([]string, error) {
	files, err := s.list()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, p := range files {
		out = append(out, strings.TrimSuffix(filepath.Base(p), ".asc"))
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) list() ([]string, error) {
	return filepath.Glob(filepath.Join(s.dir, "*.asc"))
}
