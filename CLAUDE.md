# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`veripkg` — a single static Go binary that verifies files downloaded **outside**
the package manager (bootstrap `.deb`/`.rpm`, `curl | bash` install scripts,
AppImages, tarballs) against a trusted expected value. It deliberately does *not*
duplicate what apt/dnf/pacman already do for repo installs. Zero runtime
dependencies (pure-Go OpenPGP, no system `gpg`).

## Commands

```bash
go build -o veripkg ./cmd/veripkg   # build the binary
go test ./...                       # run all tests (unit + in-process integration)
go test ./internal/verify/          # test one package
go test -run TestSignedTierEndToEnd ./cmd/veripkg/   # run one test
go vet ./... && gofmt -l .          # vet + list unformatted files (gofmt -w . to fix)
```

There is no external lint/CI config yet; `go vet` + `gofmt` are the checks.

## The core invariant (do not weaken)

**Never emit a `VERIFIED` result unless the expected value came from a source
independent of the download.** A hash published on the same page as the file is
treated as `UNVERIFIED`. This honesty rule is the entire reason the tool exists;
any change that could print a passing tier without an independent anchor is a
regression, even if tests pass.

Trust tiers (see `internal/verify`): `TierSigned` > `TierPinnedHash` >
`TierUnverified`. Only the first two are `OK()`. Exit codes are part of the
public contract: `0` verified, `2` unverified/refused, `1` operational error
(see constants in `cmd/veripkg/main.go`).

## Architecture

The design separates **I/O-free decision logic** from **orchestration/I/O** so the
security-critical path is unit-testable in isolation.

- `internal/verify` — the trust-tier decision logic. **Pure, no I/O.** Given an
  already-computed file hash plus parsed/verified inputs, it decides the tier.
  Every path that can emit a `VERIFIED` tier has a dedicated test here. Start here
  when reasoning about correctness.
- `cmd/veripkg/verifyone.go` — the orchestrator (`verifyOne`) that wires I/O
  around `internal/verify`: resolves the local file, hashes it, fetches sums/sig,
  checks the signature against the keystore, then calls the pure decision
  functions. Precedence: signed tier is attempted first; a `--hash` pin is only a
  fallback when signing material is absent or the signed attempt refuses.
  Operational failures return an `error` (exit 1); tier outcomes return a
  `verify.Result` (exit 0/2).
- Supporting I/O units, each with one job: `internal/hasher` (SHA-256),
  `internal/sumsfile` (SHA256SUMS parsing + base-name lookup fallback),
  `internal/pgp` (detached-signature verification, armored or binary),
  `internal/keystore` (explicitly trusted keys on disk; a key is trusted only
  after `trust-key`), `internal/fetcher` (local / `file://` / `https`, with size
  cap + timeout), `internal/manifest` (pinned entries for idempotent re-check).
- `cmd/veripkg/*.go` — thin CLI: `main.go` dispatch, `cmd_verify.go`,
  `cmd_pin.go`, `cmd_keys.go` (trust-key + keys), `output.go` (human + `--json`).

### Three trust anchors (why this is not "verify the package's GPG signature")

Understanding this prevents wrong "improvements". There are three different,
separately-keyed mechanisms in the Debian world:

1. Repo signature (`InRelease`/`Release.gpg`, repo key) — what apt checks
   automatically; veripkg does **not** touch this.
2. Inline package signature (`dpkg-sig`, package key) — deprecated; veripkg does
   **not** do this.
3. Detached signature over a checksums file (`SHA256SUMS` + `.asc`) — this is
   what veripkg's signed tier verifies.

See the README FAQ for the full explanation and the ProtonVPN case.

## Testing conventions

- Tests are table-driven and generate their own crypto fixtures at runtime
  (`openpgp.NewEntity`, `ArmoredDetachSign`) — there is no committed `testdata/`.
- `cmd/veripkg/integration_test.go` drives the CLI in-process via `run(args,
  stdout, stderr)` (not by shelling out to a built binary), asserting exit code +
  output for every tier, refusals, tampering, manifest re-check, and `--json`.

## Deliberate choices to preserve

- Manifest is `veripkg.json` (stdlib `encoding/json`), **not** TOML — chosen to
  keep the dependency/supply-chain surface minimal for a security tool.
- PGP is pure-Go (ProtonMail `go-crypto/openpgp`) so the binary stays
  self-contained; do not reintroduce a dependency on system `gpg`.
