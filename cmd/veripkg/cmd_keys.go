package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Taresu/veripkg/internal/fetcher"
	"github.com/Taresu/veripkg/internal/keystore"
)

func keystoreDefault() string { return keystore.DefaultDir() }

// cmdTrustKey records a GPG public key as trusted. This is the explicit act of
// trust that makes a later VERIFIED (signed) result meaningful. veripkg prints
// the resulting fingerprint(s) so the user can confirm them out-of-band.
func cmdTrustKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", keystoreDefault(), "config directory for trusted keys")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: veripkg trust-key <keyfile-or-url>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		return errf(stderr, "trust-key requires one key file or URL")
	}
	data, err := fetcher.Fetch(context.Background(), fs.Arg(0))
	if err != nil {
		return errf(stderr, "%v", err)
	}
	store, err := keystore.Open(*config)
	if err != nil {
		return errf(stderr, "%v", err)
	}
	added, err := store.Trust(data)
	if err != nil {
		return errf(stderr, "%v", err)
	}
	for _, fpr := range added {
		fmt.Fprintf(stdout, "trusted key %s\n", fpr)
	}
	fmt.Fprintln(stderr, "confirm these fingerprints against an independent source before relying on them.")
	return exitVerified
}

// cmdKeys lists trusted key fingerprints.
func cmdKeys(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", keystoreDefault(), "config directory for trusted keys")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	store, err := keystore.Open(*config)
	if err != nil {
		return errf(stderr, "%v", err)
	}
	fprs, err := store.Trusted()
	if err != nil {
		return errf(stderr, "%v", err)
	}
	if len(fprs) == 0 {
		fmt.Fprintln(stdout, "no trusted keys")
		return exitVerified
	}
	for _, f := range fprs {
		fmt.Fprintln(stdout, f)
	}
	return exitVerified
}
