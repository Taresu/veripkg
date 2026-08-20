package manifest

import (
	"path/filepath"
	"testing"
)

func TestLoadMissingReturnsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "veripkg.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 0 {
		t.Fatalf("expected empty manifest, got %d entries", len(m.Entries))
	}
}

func TestSaveLoadRoundTripAndUpsert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "veripkg.json")
	m, _ := Load(path)

	m.Upsert(Entry{Name: "zeta", File: "z.deb", Hash: "aa", Tier: "VERIFIED (pinned hash)"})
	m.Upsert(Entry{Name: "alpha", File: "a.deb", Hash: "bb", Tier: "VERIFIED (signed)"})
	// Upsert same name replaces rather than duplicates.
	m.Upsert(Entry{Name: "zeta", File: "z2.deb", Hash: "cc", Tier: "VERIFIED (pinned hash)"})

	if err := Save(path, m); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got.Entries))
	}
	// Sorted by name: alpha before zeta.
	if got.Entries[0].Name != "alpha" || got.Entries[1].Name != "zeta" {
		t.Fatalf("entries not sorted: %+v", got.Entries)
	}
	if got.Entries[1].File != "z2.deb" || got.Entries[1].Hash != "cc" {
		t.Fatalf("upsert did not replace: %+v", got.Entries[1])
	}
}
