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
- `baseline` (bulk-accept current state) and `accept` (approve a single
  port) commands for declaring expected state.
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

### Known limitations

See the README's [Limitations](README.md#limitations) and
[Roadmap](README.md#roadmap) sections — documented deliberately, not as
missing-feature surprises. Most notably: no automatic network discovery,
no Nmap XML import, and `baseline` does not prune stale expected-state
entries for ports no longer observed.
