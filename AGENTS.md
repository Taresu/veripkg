# AGENTS.md

Guidance for AI coding agents working in this repository. (Claude Code users:
see `CLAUDE.md` for the same guidance plus deeper architecture notes.)

## Build, test, lint

```bash
go build ./...                       # build
go test ./...                        # all tests (unit + in-process integration)
go test -run TestName ./pkg/path/    # a single test
go vet ./... && gofmt -l .           # must be clean; gofmt -w . to fix
```

CI runs `gofmt` (fails on any unformatted file), `go vet`, and `go test -race`.
Match that locally before proposing changes.

## The one invariant you must not weaken

`veripkg` verifies files downloaded **outside** the package manager and reports a
trust tier. **Never emit a `VERIFIED` result unless the expected value came from a
source independent of the download.** A hash from the same page as the file is
`UNVERIFIED`. The tier-decision logic lives in `internal/verify` (pure, no I/O)
and is the security core — every path that can print `VERIFIED` has a test. Any
change that could produce a passing tier without an independent anchor is a
regression, even if tests pass.

Exit codes are contract: `0` verified, `2` unverified/refused, `1` operational.

## Layout

I/O-free decision logic (`internal/verify`) is separated from orchestration/I/O
(`cmd/veripkg/verifyone.go`) and single-purpose units: `hasher`, `sumsfile`,
`pgp` (pure-Go OpenPGP — do not add a system `gpg` dependency), `keystore`,
`fetcher`, `manifest`. See `CLAUDE.md` for the full map.

## Commit conventions

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`, `ci:`; scopes like `feat(cli):` welcome).
- **Atomic**: one self-contained logical change per commit; each commit builds.

See `CONTRIBUTING.md` for the full workflow.
