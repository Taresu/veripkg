package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/tsalada/veripkg/internal/hasher"
)

// fixture builds a self-contained signed-download scenario in a temp dir:
// an artifact, a SHA256SUMS listing it, a detached signature over the sums,
// and the signer's public key. It returns the paths and a fresh config dir.
type fixture struct {
	dir      string
	config   string
	artifact string
	sums     string
	sig      string
	keyfile  string
	hash     string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	cfg := t.TempDir()

	artifact := filepath.Join(dir, "app.deb")
	if err := os.WriteFile(artifact, []byte("pretend package bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := hasher.SHA256File(artifact)
	if err != nil {
		t.Fatal(err)
	}

	sums := filepath.Join(dir, "SHA256SUMS")
	sumsContent := h + "  app.deb\n"
	if err := os.WriteFile(sums, []byte(sumsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	e, err := openpgp.NewEntity("Upstream", "", "up@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(dir, "SHA256SUMS.asc")
	var sigBuf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sigBuf, e, strings.NewReader(sumsContent), nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sig, sigBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	keyfile := filepath.Join(dir, "signer.key")
	var keyBuf bytes.Buffer
	if err := e.Serialize(&keyBuf); err != nil { // binary public key
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfile, keyBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	return fixture{dir, cfg, artifact, sums, sig, keyfile, h}
}

// runCLI executes the CLI in-process and returns exit code + stdout.
func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestSignedTierEndToEnd(t *testing.T) {
	f := newFixture(t)

	if code, _, _ := runCLI("trust-key", "--config", f.config, f.keyfile); code != exitVerified {
		t.Fatalf("trust-key exit = %d", code)
	}
	code, out, _ := runCLI("verify", "--config", f.config, "--sums", f.sums, "--sig", f.sig, f.artifact)
	if code != exitVerified {
		t.Fatalf("signed verify exit = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "VERIFIED (signed)") {
		t.Fatalf("expected signed tier, got: %s", out)
	}
}

func TestSignedRefusedWithoutTrust(t *testing.T) {
	f := newFixture(t)
	// Did NOT trust the key. Must refuse, not pass.
	code, out, _ := runCLI("verify", "--config", f.config, "--sums", f.sums, "--sig", f.sig, f.artifact)
	if code != exitRefused {
		t.Fatalf("expected refusal exit %d, got %d (%s)", exitRefused, code, out)
	}
	if !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("expected UNVERIFIED, got: %s", out)
	}
}

func TestPinnedHashTier(t *testing.T) {
	f := newFixture(t)
	code, out, _ := runCLI("verify", "--hash", f.hash, f.artifact)
	if code != exitVerified || !strings.Contains(out, "VERIFIED (pinned hash)") {
		t.Fatalf("pinned-hash verify: code=%d out=%s", code, out)
	}
}

func TestRefusalNoSource(t *testing.T) {
	f := newFixture(t)
	code, out, _ := runCLI("verify", f.artifact)
	if code != exitRefused || !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("expected refusal, code=%d out=%s", code, out)
	}
}

func TestTamperedFileFailsSigned(t *testing.T) {
	f := newFixture(t)
	runCLI("trust-key", "--config", f.config, f.keyfile)
	if err := os.WriteFile(f.artifact, []byte("tampered!"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI("verify", "--config", f.config, "--sums", f.sums, "--sig", f.sig, f.artifact)
	if code != exitRefused {
		t.Fatalf("tampered file should refuse, code=%d out=%s", code, out)
	}
}

func TestPinThenRecheckManifest(t *testing.T) {
	f := newFixture(t)
	mani := filepath.Join(f.dir, "veripkg.json")

	code, _, errs := runCLI("pin", "--manifest", mani, "--hash", f.hash, "app", f.artifact)
	if code != exitVerified {
		t.Fatalf("pin exit=%d err=%s", code, errs)
	}
	// Idempotent re-check with no file argument.
	code, out, _ := runCLI("verify", "--manifest", mani, "--config", f.config)
	if code != exitVerified {
		t.Fatalf("manifest recheck exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "VERIFIED") {
		t.Fatalf("recheck output: %s", out)
	}
}

func TestJSONOutput(t *testing.T) {
	f := newFixture(t)
	code, out, _ := runCLI("verify", "--json", "--hash", f.hash, f.artifact)
	if code != exitVerified {
		t.Fatalf("json verify exit=%d", code)
	}
	if !strings.Contains(out, `"ok": true`) || !strings.Contains(out, `"tier": "VERIFIED (pinned hash)"`) {
		t.Fatalf("unexpected json: %s", out)
	}
}
