package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/Taresu/veripkg/internal/manifest"
)

// cmdPin verifies a file and, only if it passes, records it in the manifest so
// it can be re-checked later with a bare `veripkg verify`. Pinning a file that
// does not verify is refused — the manifest only ever holds trusted entries.
func cmdPin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		sums     = fs.String("sums", "", "URL/path to SHA256SUMS")
		sig      = fs.String("sig", "", "URL/path to the detached signature over the sums")
		key      = fs.String("key", "", "require this signing-key fingerprint")
		hash     = fs.String("hash", "", "expected sha256 hex (pinned-hash tier)")
		config   = fs.String("config", keystoreDefault(), "config directory for trusted keys")
		manifile = fs.String("manifest", manifest.DefaultName, "manifest path to write")
		asJSON   = fs.Bool("json", false, "machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: veripkg pin <name> <file> [--sums URL --sig URL | --hash HEX]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 2 {
		return errf(stderr, "pin requires <name> and <file>")
	}
	name, file := fs.Arg(0), fs.Arg(1)

	r, err := verifyOne(context.Background(), verifyInput{
		file: file, name: name, sumsRef: *sums, sigRef: *sig,
		keyReq: *key, hash: *hash, configDir: *config,
	})
	if err != nil {
		return errf(stderr, "%v", err)
	}
	code := report(stdout, r, *asJSON)
	if !r.Tier.OK() {
		fmt.Fprintln(stderr, "refusing to pin: verification did not pass")
		return code
	}

	m, err := manifest.Load(*manifile)
	if err != nil {
		return errf(stderr, "%v", err)
	}
	// Store the file path relative to the manifest when possible, for portability.
	stored := file
	if rel, rerr := filepath.Rel(filepath.Dir(*manifile), file); rerr == nil {
		stored = rel
	}
	m.Upsert(manifest.Entry{
		Name: name, File: stored, Hash: r.ExpectedHash,
		SumsURL: *sums, SigURL: *sig, KeyFingerprint: r.KeyFingerprint,
		Tier: r.Tier.String(),
	})
	if err := manifest.Save(*manifile, m); err != nil {
		return errf(stderr, "%v", err)
	}
	fmt.Fprintf(stdout, "pinned %q to %s\n", name, *manifile)
	return exitVerified
}
