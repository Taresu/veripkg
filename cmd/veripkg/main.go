// Command veripkg verifies files downloaded outside the package manager
// against a trusted expected value, and reports which trust tier was achieved.
//
// It exists because package managers already verify repo packages
// cryptographically, but files you fetch by hand — bootstrap .debs, install
// scripts, AppImages, tarballs — get no such check. veripkg fills that gap
// without ever reporting success unless the expected value came from a source
// independent of the download.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes form part of the tool's contract (scripts/CI depend on them).
const (
	exitVerified = 0 // a passing trust tier was achieved
	exitError    = 1 // operational failure (bad flags, I/O, network)
	exitRefused  = 2 // ran fine but could not verify: UNVERIFIED/refused
)

const banner = `
__     __ _____  ____   ___  ____   _  __  ____
\ \   / /| ____||  _ \ |_ _||  _ \ | |/ / / ___|
 \ \ / / |  _|  | |_) | | | | |_) || ' /| |  _
  \ V /  | |___ |  _ <  | | |  __/ | . \| |_| |
   \_/   |_____||_| \_\|___||_|    |_|\_\ \____|
`

const usage = `veripkg — verify out-of-band downloads against a trusted source

USAGE:
    veripkg <command> [options]

COMMANDS:
    verify       Verify a file (or, with no file, re-check the manifest)
    pin          Verify a file and record it in the manifest for re-checking
    trust-key    Record a GPG public key as trusted (for signed verification)
    keys         List trusted key fingerprints
    version      Print version

Run "veripkg <command> -h" for command-specific options.

TRUST TIERS (printed on every verification):
    VERIFIED (signed)        file matched a SHA256SUMS signed by a trusted key
    VERIFIED (pinned hash)   file matched a hash you recorded earlier
    UNVERIFIED               no independent trusted source — treated as failure
`

var version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "%s\n%s", banner, usage)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "pin":
		return cmdPin(rest, stdout, stderr)
	case "trust-key":
		return cmdTrustKey(rest, stdout, stderr)
	case "keys":
		return cmdKeys(rest, stdout, stderr)
	case "version", "--version", "-v":
		// Banner to stderr keeps stdout a clean, parseable version line.
		fmt.Fprintf(stderr, "%s\n", banner)
		fmt.Fprintf(stdout, "veripkg %s\n", version)
		return exitVerified
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, "%s\n%s", banner, usage)
		return exitVerified
	default:
		fmt.Fprintf(stderr, "%s\nunknown command %q\n\n%s", banner, cmd, usage)
		return exitError
	}
}

func errf(w io.Writer, format string, a ...any) int {
	fmt.Fprintf(w, "error: "+format+"\n", a...)
	return exitError
}
