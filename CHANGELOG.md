# Changelog

All notable changes to PortPeek are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-09

Initial release. A usable, complete first release, not a throwaway
prototype.

### Added

- Asset management: `add`, `list`, `remove`.
- Lightweight, non-destructive TCP connect scanner (`scan`) with
  configurable port specs (`--ports`, e.g. `22,80,443` or `1-1000`),
  timeout, and concurrency.
- Service fingerprinting for SSH, HTTP, HTTPS, FTP, SMTP, MySQL/MariaDB,
  PostgreSQL, and Redis, each with explicit `confidence` and `evidence`,
  plus an honest "Unknown TCP service" fallback.
- Distinct `open` / `closed` / `filtered` / `timeout` port states
  (never collapsed together).
- SQLite-backed persistent state: assets, scans, observations, expected
  (baseline) state, and events — a single database file, no external
  dependencies.
- `baseline` (bulk-accept the latest scan's observed state, including
  pruning stale expected-open entries for ports now definitively observed
  closed) and `accept` (approve a single port) commands for declaring
  expected state, both applied transactionally and reconciling every
  active event kind for the ports they touch.
- `diff` command and diff-aware `scan` exit codes, comparing current
  observations against expected state.
- Two-scan confirmation for all drift events (`NEW_PORT`, `PORT_CLOSED`,
  `SERVICE_CHANGED`, `SERVICE_DISAPPEARED`, `EXPECTED_SERVICE_MISSING`),
  with full pending → confirmed → accepted/resolved lifecycle.
- Documented, stable exit codes (`0` clean, `1` confirmed drift, `2`
  error, `3` pending/unconfirmed drift) for use in cron/systemd/CI.
- `--json` output on every meaningful command, with a stable, documented
  schema and no mixed-in terminal decoration.
- `history` command, including per-port history.
- `cleanup` command with configurable retention, always preserving each
  asset's latest scan.
- `--no-save` for temporary, non-persisted scans.
- Vantage-point tracking: every scan records where it was run from, and
  PortPeek never claims "publicly exposed" without evidence of a public
  vantage point.
- Flags may be given before or after positional arguments.
- Full unit and integration test suite (`internal/scanner`,
  `internal/fingerprint`, `internal/diff`, `internal/storage`,
  `internal/events`, and CLI-level exit-code tests), fully offline and
  deterministic.
- GitHub Actions CI (`go build`, `go test ./...`, `go vet ./...`, `gofmt`
  check) across a small Go version matrix.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/design.md`, and
  example scripts under `examples/`.

### Fixed (pre-release hardening)

Found and fixed during release review, before this version's first public
publish:

- **Fingerprinting crashes.** A malformed or truncated SSH banner (e.g.
  `SSH-2.0-` with nothing after the final dash) could panic the scanner.
  All banner parsers are now defensive against malformed, empty, or
  adversarial input, with a panic-recovery boundary around every probe as
  defense in depth, plus regression tests including fuzz-style random byte
  payloads.
- **False drift confirmation from uncertain reads.** `filtered`/`timeout`
  observations could previously be treated as evidence that a port had
  closed or that an expected service had gone missing, confirming drift
  (and flipping the exit code) off a single dropped packet. Uncertain
  reads are now never treated as evidence of anything, at both the diff
  and event-confirmation layers, including a `PORT_CLOSED` shortcut that
  used to confirm immediately instead of going through the same two-scan
  confirmation as every other event kind.
- **`baseline` semantics.** Rewritten to be state-aware and transactional:
  see the `baseline` section above and [Limitations](README.md#limitations)
  for current, accurate behavior.
- **`accept` on a closed port.** `accept` used to unconditionally record a
  port as expected-*open* regardless of its actual latest state. Combined
  with clearing every active event kind, accepting a port that had just
  been confirmed closed (a `PORT_CLOSED` finding) would simultaneously
  clear that event and insert a contradictory expected-open entry for a
  port that was, in fact, closed - producing a brand-new, duplicate
  `EXPECTED_SERVICE_MISSING` finding on the very next scan for the exact
  condition just accepted. `accept` is now state-aware the same way
  `baseline` is: accepting a definitively-closed port removes any stale
  expected-open entry instead of creating one.
- **`baseline` missing never-baselined `PORT_CLOSED` findings.** `baseline`
  previously only swept a port's active events when it found an existing
  expected-open entry to remove. A `PORT_CLOSED` event, by design, tracks a
  port that was *never* formally baselined (an unexpected exposure that
  later closed on its own) - so such a port had no expected-open entry to
  remove, and its confirmed `PORT_CLOSED` event was unreachable by
  `baseline`, staying confirmed (and contributing to exit code 1)
  indefinitely with no bulk way to clear it. `baseline` now acknowledges
  every definitively-closed port it observes, with or without a prior
  expectation - see `acknowledged_ports` in the `baseline` section above.
- **Schema-version handling.** `Open()` previously stamped its own
  (possibly older) schema version over whatever was already recorded on
  every single open, unconditionally - silently masking the case where a
  database had last been written by a newer release of PortPeek than the
  one now opening it, and risking that older build operating on tables or
  columns it doesn't understand. `Open()` now reads the recorded version
  first and refuses to open a database whose schema is newer than it
  understands (`storage.ErrSchemaTooNew`), and has a defined (currently
  empty, since this is still the only schema version that has ever
  shipped) place for future non-destructive migrations to live.
- **CI never actually ran.** `.github/workflows/ci.yml` triggered on
  `branches: [main]`, but this repository's branch is `master` - every
  push and pull request was silently ignored by CI. Fixed to trigger on
  `master`, bumped the Go version matrix from two now-unsupported minor
  versions (1.21/1.22) to the two currently-supported Go major releases
  (1.26/1.27 as of this review), and bumped `actions/checkout`/
  `actions/setup-go` to their current major versions (v5/v6).

### Known limitations

See the README's [Limitations](README.md#limitations) and
[Roadmap](README.md#roadmap) sections — documented deliberately, not as
missing-feature surprises. Most notably: no automatic network discovery,
no Nmap XML import, and `baseline` only prunes a stale expected-state
entry when it has a definitive closed reading for that port in the same
scan.
