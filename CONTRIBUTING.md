# Contributing to PortPeek

Thanks for your interest in PortPeek. This document covers how to get a
development environment running, the project's expectations for changes,
and the overall philosophy that guides what does and doesn't belong here.

## Philosophy, briefly

PortPeek is **not** trying to compete with Nmap or become a general-purpose
scanner. Its job is narrow and specific: scan → observe → remember →
compare → explain. The scanner is the input; the state engine (storage,
diff, events) is the product. Keep that in mind before proposing scope
expansions — see [Project scope](#project-scope) below.

PortPeek also maintains a conservative, authorized-use-only safety
posture. Contributions that add exploitation, credential attacks, brute
forcing, vulnerability exploitation, or stealth/evasion capabilities will
not be accepted, regardless of how they're framed.

## Getting started

### Prerequisites

- Go 1.21 or newer.
- A C toolchain (gcc/clang), since the SQLite driver uses cgo.
- `git`.

### Clone and build

```bash
git clone https://github.com/rithinkrishnakv/portpeek.git
cd portpeek
make build
./bin/portpeek version
```

### Run the test suite

```bash
make test          # go test ./...
go test -race ./... # recommended before submitting a PR
make lint           # go vet + gofmt check (+ staticcheck if installed)
```

All tests are deterministic and run fully offline — they spin up local
TCP listeners (`127.0.0.1:0`) to exercise the scanner and fingerprinting
code rather than depending on any real network service. If you add a test
that depends on an external network resource, it will be rejected; please
write it against a local fake server instead (see existing tests in
`internal/scanner`, `internal/fingerprint`, and `cmd/portpeek/cli_test.go`
for the established pattern).

### Project layout

```
cmd/portpeek/        CLI entry point and per-command logic
internal/config/      Defaults and path resolution
internal/version/     Version string (ldflags-overridable git commit)
internal/scanner/      TCP connect scanning
internal/fingerprint/  Non-destructive service fingerprinting
internal/storage/      SQLite persistence (assets, scans, observations, expected, events)
internal/diff/          Pure comparison logic: observations vs. expected -> candidates
internal/events/        Two-scan confirmation lifecycle on top of internal/diff
internal/output/        Human-readable and JSON rendering
docs/                   Design notes
examples/                Example shell scripts
```

`internal/diff` is deliberately a pure function package (no DB, no
network) so its logic can be exhaustively unit tested in isolation.
`internal/events` owns the stateful parts (touching/confirming/resolving
events in storage) on top of it. If you're changing drift-detection
behavior, you almost certainly want to touch `internal/diff` first and
add a test there before touching anything else.

## Making changes

1. Open an issue first for anything beyond a small bug fix, so we can
   discuss the approach before you invest time in it.
2. Write tests for your change. New behavior without a test won't be
   merged. See the existing suite for the expected style — local fake
   servers, `t.TempDir()`-backed SQLite databases, no network
   dependencies, no sleeps where a channel or a real timeout works.
3. Run `make test`, `go test -race ./...`, and `make lint` locally before
   opening a PR. CI runs the same checks across a small Go version
   matrix, plus `staticcheck`.
4. Keep commits focused. A PR that fixes a bug and a PR that adds a
   feature are two PRs.
5. Update `README.md` and `CHANGELOG.md` when your change affects
   documented behavior, flags, or output.

### Code style

- Run `gofmt` (or `make fmt`) before committing.
- Prefer clear, explicit code over clever code. This is a security tool;
  readability and auditability matter more than terseness.
- Never invent or guess at data. If PortPeek doesn't know something (a
  service name, a version), say so explicitly (e.g. `"Unknown TCP
  service"`) rather than omitting the field or guessing. See
  `docs/design.md` for why this matters in practice.
- JSON output is a stable, documented contract (see `internal/output`).
  Don't add, rename, or remove JSON fields without discussing the
  compatibility impact in your PR description.

## Project scope

In scope:

- Bug fixes, including in the diff/event engine's drift-detection logic.
- Additional non-destructive service fingerprints (same conservative
  safety posture as the existing ones — see `internal/fingerprint`'s
  doc comments for the reasoning behind what's probed and what isn't).
- Import of observations from other non-destructive sources (e.g., Nmap
  XML) into the same storage/diff/events pipeline — this is an explicit
  roadmap item; the architecture already separates "observation source"
  from "state engine" to make this possible without a rewrite.
- Usability improvements to the CLI, output formatting, and docs.

Out of scope (will be declined):

- Exploitation, credential attacks, brute forcing, or vulnerability
  scanning/claims.
- Stealth/evasion techniques (fragmentation, timing evasion, decoys,
  etc.).
- Automatic network discovery/host enumeration in v1 (tracked as a
  future possibility, but deliberately not in the initial design — see
  `docs/design.md`).
- Cloud sync, accounts, telemetry, or any "phone home" behavior. PortPeek
  is local-first and stays that way.

## Reporting bugs

Please include:

- PortPeek version (`portpeek version`).
- OS/architecture.
- Exact command run and full output (redact any sensitive hostnames/IPs
  if needed, but keep the structure).
- What you expected vs. what happened.

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for how to report them privately.
