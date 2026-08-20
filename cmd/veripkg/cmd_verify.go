package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/tsalada/veripkg/internal/manifest"
)

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		sums     = fs.String("sums", "", "URL/path to SHA256SUMS (with -sig, enables signed verification)")
		sig      = fs.String("sig", "", "URL/path to the detached signature over the sums file")
		key      = fs.String("key", "", "require this signing-key fingerprint (full fingerprint recommended)")
		hash     = fs.String("hash", "", "expected sha256 hex (pinned-hash tier)")
		name     = fs.String("name", "", "name to look up in the sums file (default: file's base name)")
		config   = fs.String("config", keystoreDefault(), "config directory for trusted keys")
		manifile = fs.String("manifest", manifest.DefaultName, "manifest path for no-argument re-check")
		asJSON   = fs.Bool("json", false, "machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: veripkg verify <file> [options]\n"+
			"   or: veripkg verify            (re-check every entry in the manifest)\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	// No file argument → re-check the manifest (idempotent).
	if fs.NArg() == 0 {
		return recheckManifest(*manifile, *config, *asJSON, stdout, stderr)
	}
	if fs.NArg() > 1 {
		return errf(stderr, "verify takes at most one file (got %d)", fs.NArg())
	}

	in := verifyInput{
		file:      fs.Arg(0),
		name:      *name,
		sumsRef:   *sums,
		sigRef:    *sig,
		keyReq:    *key,
		hash:      *hash,
		configDir: *config,
	}
	r, err := verifyOne(context.Background(), in)
	if err != nil {
		return errf(stderr, "%v", err)
	}
	return report(stdout, r, *asJSON)
}

// recheckManifest re-verifies every pinned entry. Exit code is verified only if
// all entries pass; any refusal yields exitRefused, any operational error exitError.
func recheckManifest(path, config string, asJSON bool, stdout, stderr io.Writer) int {
	m, err := manifest.Load(path)
	if err != nil {
		return errf(stderr, "%v", err)
	}
	if len(m.Entries) == 0 {
		return errf(stderr, "no manifest entries to check (looked in %s)", path)
	}
	base := filepath.Dir(path)
	worst := exitVerified
	for _, e := range m.Entries {
		file := e.File
		if !filepath.IsAbs(file) {
			file = filepath.Join(base, file)
		}
		r, err := verifyOne(context.Background(), verifyInput{
			file: file, name: e.Name, sumsRef: e.SumsURL, sigRef: e.SigURL,
			keyReq: e.KeyFingerprint, hash: e.Hash, configDir: config,
		})
		if err != nil {
			fmt.Fprintf(stderr, "error: %s: %v\n", e.Name, err)
			worst = exitError
			continue
		}
		code := report(stdout, r, asJSON)
		if code == exitRefused && worst == exitVerified {
			worst = exitRefused
		}
	}
	return worst
}
