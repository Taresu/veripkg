```
__     __ _____  ____   ___  ____   _  __  ____
\ \   / /| ____||  _ \ |_ _||  _ \ | |/ / / ___|
 \ \ / / |  _|  | |_) | | | | |_) || ' /| |  _
  \ V /  | |___ |  _ <  | | |  __/ | . \| |_| |
   \_/   |_____||_| \_\|___||_|    |_|\_\ \____|
```

# veripkg

**Verify the files you download by hand — before you run them as root.**

`veripkg` is a small, dependency-free CLI that checks a downloaded file
(bootstrap `.deb`/`.rpm`, `install.sh`, AppImage, tarball) against a **trusted**
expected value, and tells you *honestly* how much that check is worth.

It exists to close one specific, real gap — and it refuses to lie to you about
the rest.

---

## Why this matters (the honest version)

Your package manager already protects you *most* of the time. When you
`apt install` or `dnf install` from a configured repository, the package is
verified against a **GPG-signed index** automatically. Tampered packages fail
that check and never install. **veripkg does not try to replace this, and you
don't need it for normal repo installs.**

But look at how real software actually asks you to install it:

```bash
# The pattern that has no automatic protection:
curl -fsSL https://get.example.com/install.sh | bash
wget https://downloads.example.com/app.deb && sudo dpkg -i app.deb
```

Every one of these fetches code **outside** the package manager and often runs
it **as root** — with *zero* automatic integrity or authenticity checking. This
is the single biggest unguarded step in day-to-day Linux usage, on every distro.
That is the gap veripkg fills.

### The catch most "checksum tools" ignore

You've seen instructions like:

> Verify the download: `echo "0b14e715… file.deb" | sha256sum --check -`

Here's the uncomfortable truth: **if the hash comes from the same page as the
file, it protects you against a corrupted download — not against an attacker.**
Whoever can swap the file can swap the hash next to it. A green checkmark there
is *reassuring* but not *secure*.

veripkg is built around that truth. **It will not show a "verified" result
unless the expected value came from a source independent of the download.**

---

## Trust tiers — printed on every run

veripkg never gives you an unqualified ✓. Every result states exactly what was
proven:

| Tier | What it means | Protects against |
|------|---------------|------------------|
| **VERIFIED (signed)** | File's hash was in a `SHA256SUMS` whose **GPG signature** verified against a key **you explicitly trusted**. | Corruption **and** tampering. Real authenticity. |
| **VERIFIED (pinned hash)** | File matched a hash **you recorded earlier**. | Corruption, and tampering **only if your pinned hash came from a trustworthy source**. |
| **UNVERIFIED** | No independent trusted source. **Exit code 2.** | Nothing. veripkg refuses to pretend otherwise. |

This labeling *is* the product. The hashing is easy; being honest about what a
check does and does not prove is the point.

---

## What you actually get

- **Real protection for the unprotected step** — the manual downloads and
  `curl | bash` installers your package manager never sees.
- **Genuine authenticity when upstream supports it** — pure-Go OpenPGP
  verification of signed `SHA256SUMS`, so you learn *who* signed a file, not
  just that its bytes are intact.
- **Honesty by design** — no false confidence. A same-origin hash is treated as
  UNVERIFIED, because that's what it is.
- **Repeatable & CI-friendly** — pin a verified file once, then re-check it
  forever with a single idempotent command and a clean exit code.
- **Runs everywhere, installs nothing** — a single static binary. No `gpg`, no
  Python, no runtime deps. Works the same on Debian, Ubuntu, Fedora, Arch,
  Alpine, containers, and macOS. Prebuilt for Linux (amd64/arm64/arm) and
  macOS (amd64/arm64).

---

## Install

Download the static binary for your architecture from
[Releases](https://github.com/Taresu/veripkg/releases),
or install with Go:

```bash
go install github.com/Taresu/veripkg/cmd/veripkg@latest
```

Or build from source:

```bash
go build -o veripkg ./cmd/veripkg
sudo mv veripkg /usr/local/bin/
```

## Usage

### Strongest: signed SHA256SUMS

Many projects publish a `SHA256SUMS` plus a detached GPG signature. Trust the
signing key once (confirm its fingerprint against an independent source — the
project's website over HTTPS, a keyserver, a second machine), then verify:

```bash
veripkg trust-key upstream-signing-key.asc
# → trusted key ABCD… ; confirm this fingerprint out-of-band.

veripkg verify app-1.2.3.tar.gz \
  --sums https://example.com/SHA256SUMS \
  --sig  https://example.com/SHA256SUMS.asc
# ✓ VERIFIED (signed)  app-1.2.3.tar.gz
```

#### Worked example: HashiCorp Terraform

A real, reproducible run. Terraform publishes a GPG-signed `SHA256SUMS`, signed
by HashiCorp's release **subkey** under their published primary key:

```bash
V=1.9.8 ; B=https://releases.hashicorp.com/terraform/$V

# Trust HashiCorp's key once (confirm the fingerprint at hashicorp.com/security).
curl -sO https://www.hashicorp.com/.well-known/pgp-key.txt
veripkg trust-key pgp-key.txt
# → trusted key C874011F0AB405110D02105534365D9472D7468F

curl -sO $B/terraform_${V}_linux_amd64.zip
curl -sO $B/terraform_${V}_SHA256SUMS
curl -sO $B/terraform_${V}_SHA256SUMS.sig

veripkg verify terraform_${V}_linux_amd64.zip \
  --sums terraform_${V}_SHA256SUMS \
  --sig  terraform_${V}_SHA256SUMS.sig \
  --key  C874011F0AB405110D02105534365D9472D7468F
# ✓ VERIFIED (signed)  terraform_1.9.8_linux_amd64.zip
#     matched signed sums (key C874011F0AB405110D02105534365D9472D7468F)
```

Change one byte of the zip and the same command exits `2` with a hash mismatch —
the check is real, not decorative.

### Fallback: pinned hash (e.g. the ProtonVPN case)

When upstream only prints a bare hash (no signed sums), record it as a pin. Get
the hash from the most independent source you can, then:

```bash
veripkg verify protonvpn-stable-release_1.0.8_all.deb \
  --hash 0b14e71586b22e498eb20926c48c7b434b751149b1f2af9902ef1cfe6b03e180
# ✓ VERIFIED (pinned hash)   (integrity vs. your pin only)
```

### Repeatable: pin once, re-check forever

```bash
veripkg pin protonvpn app.deb --hash 0b14e715…   # writes veripkg.json
veripkg verify                                    # re-checks everything; exit 0/2
```

Drop `veripkg verify` into CI or a provisioning script to catch a silently
changed artifact.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Verified (a passing trust tier) |
| `2` | Unverified / refused |
| `1` | Operational error (bad flags, missing file, network) |

Add `--json` to any command for machine-readable output.

---

## Honest limitations

- **It doesn't replace your package manager.** Repo installs are already
  verified; use veripkg for out-of-band downloads.
- **A pinned hash is only as trustworthy as where you got it.** veripkg makes
  the trust level explicit; it can't make a same-origin hash trustworthy.
- **It can't verify what upstream doesn't publish.** No signed sums and no
  independent hash means an honest UNVERIFIED.
- **Trusting a key is your decision.** veripkg records and reuses your choice
  and shows fingerprints; confirming a fingerprint is genuine is on you.

## FAQ

### Why not just verify the downloaded `.deb`/`.rpm`'s own GPG signature?

Because that's a different thing than most people think, and it's often the
*wrong* thing to check. There are **three distinct trust anchors**, each with
its own key:

1. **Repo signature** (`InRelease` / `Release.gpg`) — signed with the **repo
   key**. This is what `apt`/`dnf` verify automatically on every install, and it
   covers each package transitively (signed release index → package hashes).
2. **Inline package signature** (`dpkg-sig --verify`) — a signature embedded
   *inside* the `.deb`, signed with a separate **package key**. This mechanism is
   old, rarely used, and is **not** how modern package managers verify anything.
3. **Detached signature over a checksums file** (`SHA256SUMS` + `.asc`) — what
   veripkg's **VERIFIED (signed)** tier uses.

ProtonVPN's install page makes this concrete:

> Please don't try to check the GPG signature of the release package itself
> (`dpkg-sig --verify`). Our internal release process is split into several
> parts. The release package is signed with a GPG key, and the repo is signed
> with another GPG key, so the keys don't match.

That's a warning about mechanism **#2 vs #1** — don't verify the package's inline
signature and expect its key to match the repo key. **veripkg does neither #1 nor
#2.** It verifies a *detached signature over a checksums file* (#3), or a pinned
hash. So the thing ProtonVPN tells you not to do simply isn't what veripkg does —
its effectiveness is unaffected.

This is exactly why veripkg is explicit about *which* artifact it verifies against
*which* key: a naive "verify the package's signature" tool would hit these
mismatched keys and either error out or print something misleading.

### So how should I verify the ProtonVPN bootstrap `.deb`?

ProtonVPN publishes only a bare hash for it (no signed `SHA256SUMS`), so the
**VERIFIED (pinned hash)** tier is the right and only option — see the pinned-hash
example above. That bootstrap package's job is a one-time trust-establishment step
(it installs the repo config and repo signing key); from then on, `apt`'s repo
signature (#1) protects everything else. That first out-of-band fetch is precisely
where a pinned-hash check adds the most value — ideally with the hash sourced
independently of the download page.

## How it works

A single Go binary with small, independently-testable parts: `hasher`
(SHA-256), `sumsfile` (SHA256SUMS parsing), `pgp` (pure-Go OpenPGP signature
checking), `keystore` (explicit trusted keys), `fetcher` (local/`file://`/https),
`manifest` (pinned entries), and `verify` — the trust-tier decision logic, which
is covered by dedicated tests for every path that can emit a VERIFIED result.

## License

MIT.
