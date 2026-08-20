package sumsfile

import (
	"strings"
	"testing"
)

const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestParseValid(t *testing.T) {
	in := strings.Join([]string{
		"# a comment",
		"",
		abc + "  text-mode.bin",
		abc + " *binary-mode.bin",
		abc + "  ./with-dot-slash.bin",
	}, "\n")

	s, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"text-mode.bin", "binary-mode.bin", "with-dot-slash.bin"} {
		if got, ok := s.Lookup(name); !ok || got != abc {
			t.Errorf("Lookup(%q) = %q,%v", name, got, ok)
		}
	}
}

func TestLookupBaseNameFallback(t *testing.T) {
	s, err := Parse(strings.NewReader(abc + "  file.deb\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Lookup("/home/user/downloads/file.deb"); !ok || got != abc {
		t.Errorf("base-name fallback failed: %q,%v", got, ok)
	}
	if _, ok := s.Lookup("other.deb"); ok {
		t.Error("unexpected match for other.deb")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"only comments": "# nothing here\n",
		"short digest":  "abc123  file\n",
		"bad hex":       strings.Repeat("z", 64) + "  file\n",
		"no filename":   abc + "\n",
	}
	for name, in := range cases {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
