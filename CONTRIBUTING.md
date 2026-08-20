# Contributing to veripkg

Thanks for helping improve veripkg. This is a security tool, so the bar is
"correct and honest" over "clever." Contributions from humans and AI agents are
both welcome — see `AGENTS.md` / `CLAUDE.md` for agent-specific notes.

## Development workflow

```bash
go build ./...        # build
go test ./...         # run the full suite
go vet ./...          # static checks
gofmt -w .            # format (CI fails on any unformatted file)
```

Before opening a PR, make sure all of these pass. CI runs `gofmt` (as a check),
`go vet`, and `go test -race`.

> **`go install` PATH gotcha:** if you install the CLI (`go install ./cmd/veripkg`
> or `...@latest`) and hit `veripkg: command not found`, Go's bin directory isn't
> on your `PATH`. Add it: `export PATH="$PATH:$(go env GOPATH)/bin"` (persist it in
> your shell rc). See the README's Troubleshooting section for details.

## The rule that matters most

`veripkg` must **never report a `VERIFIED` tier unless the expected value came
from a source independent of the download.** The decision logic is in
`internal/verify` and is deliberately I/O-free so it can be tested in isolation.
If you touch anything that can produce a passing tier:

- add a positive test for each path that can print `VERIFIED`, and
- add a negative test for each path that must **refuse**.

Exit codes are part of the public contract: `0` verified, `2` unverified/refused,
`1` operational error. Don't change them casually.

## Commits

- Use **Conventional Commits**: `feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`, `ci:` — optionally scoped, e.g. `feat(cli):`, `test(pgp):`.
- Keep commits **atomic**: one self-contained logical change each, and every
  commit should build on its own.

## Dependencies

Keep the dependency/supply-chain surface small — this is a security tool. In
particular, PGP verification is intentionally pure-Go (ProtonMail
`go-crypto/openpgp`); do not reintroduce a runtime dependency on system `gpg`.

## Reporting security issues

If you find a vulnerability, please avoid filing a public issue with exploit
details. Open a minimal issue asking for a private contact, or use GitHub's
private security advisory feature for this repository.
