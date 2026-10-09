# PortPeek

**A local-first network exposure changelog.**

Scan → Observe → Remember → Compare → Explain.

PortPeek is not a competitor to Nmap, and it is not trying to be one. It
doesn't do deep service enumeration, OS fingerprinting, or vulnerability
scanning, and it never will. What it does is answer one specific question
well, over time: **"What changed on this network since I last checked —
and how do I know?"**

You tell PortPeek about a handful of assets you care about (a home server,
a lab box, a small fleet of machines you administer). It scans them,
remembers exactly what it saw, lets you say "yes, this is expected," and
then tells you — with evidence, not guesses — when that expectation stops
matching reality.

> **Only scan systems you own or have explicit, documented authorization
> to assess.** See [Responsible use](#responsible-use) below.

---

## Table of contents

- [Why PortPeek](#why-portpeek)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [How drift detection works](#how-drift-detection-works)
- [JSON output](#json-output)
- [Exit codes](#exit-codes)
- [Service fingerprinting](#service-fingerprinting)
- [Data storage](#data-storage)
- [Using PortPeek unattended (cron/systemd/CI)](#using-portpeek-unattended-cronsystemdci)
- [Responsible use](#responsible-use)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Development](#development)
- [License](#license)

## Why PortPeek

Most scanners answer "what's open right now?" That's useful once. It's
much less useful the tenth time you run it, because you're left doing the
comparison in your head, or in a spreadsheet, or not at all.

PortPeek is built around the idea that **the scanner is the input — the
state engine is the product.** Every scan is persisted. You declare what's
expected (a baseline). PortPeek compares. It requires the *same* finding
to show up on two consecutive scans before it calls it confirmed, so a
one-off blip doesn't turn into a false alarm. And it's honest about what
it doesn't know: an open port with no identifiable service is reported as
exactly that, never guessed at.

Everything runs locally. No accounts, no cloud sync, no telemetry, no API
keys. PortPeek only touches the network when you ask it to scan something;
otherwise it's just reading and writing a SQLite file on your own disk.

## Installation

### From source

Requires Go 1.21+ and a C toolchain (the SQLite driver uses cgo).

```bash
git clone https://github.com/rithinkrishnakv/portpeek.git
cd portpeek
make build
./bin/portpeek version
```

Install it onto your `$GOBIN`/`$PATH`:

```bash
make install
portpeek version
```

### go install

```bash
go install github.com/rithinkrishnakv/portpeek/cmd/portpeek@latest
```

## Quick start

```console
$ portpeek add demo-host 127.0.0.1
Added asset "demo-host" -> 127.0.0.1
Next: portpeek scan demo-host

$ portpeek list
LABEL                TARGET
demo-host            127.0.0.1

$ portpeek scan demo-host --ports 2222,8088,9999 --timeout 300
PortPeek

Asset: demo-host
Target: 127.0.0.1
Observed from: vm

2222/tcp OPEN   SSH        OpenSSH 9.6
8088/tcp OPEN   HTTP       nginx/1.25.3

2 open, 1 closed, 0 filtered, 0 timeout (of 3 ports checked)

• new exposure on port 2222/tcp observed for the first time - will confirm on next scan if it persists.
• new exposure on port 8088/tcp observed for the first time - will confirm on next scan if it persists.
```

A single scan never immediately declares drift — see
[How drift detection works](#how-drift-detection-works). Run it again and
the same findings confirm:

```console
$ portpeek scan demo-host --ports 2222,8088,9999 --timeout 300
PortPeek

Asset: demo-host
Target: 127.0.0.1
Observed from: vm

2222/tcp OPEN   SSH        OpenSSH 9.6
8088/tcp OPEN   HTTP       nginx/1.25.3

2 open, 1 closed, 0 filtered, 0 timeout (of 3 ports checked)

⚠ NEW EXPOSURE

Port: 2222/tcp
port is open and not present in the expected baseline (observed service: SSH)
Status: confirmed

⚠ NEW EXPOSURE

Port: 8088/tcp
port is open and not present in the expected baseline (observed service: HTTP)
Status: confirmed
```

Once you've reviewed it and decided this is the expected state of the
world, accept it as the baseline:

```console
$ portpeek baseline demo-host
Baselined 2 open port(s) on "demo-host" as expected state.
  2222/tcp  SSH
  8088/tcp  HTTP
```

From now on, as long as nothing changes, scans come back clean:

```console
$ portpeek scan demo-host --ports 2222,8088,9999 --timeout 300
PortPeek

Asset: demo-host
Target: 127.0.0.1
Observed from: vm

2222/tcp OPEN   SSH        OpenSSH 9.6
8088/tcp OPEN   HTTP       nginx/1.25.3

2 open, 1 closed, 0 filtered, 0 timeout (of 3 ports checked)

No confirmed drift.
```

See `examples/basic-workflow.sh` for this same walkthrough as a runnable
script, and `examples/cron-check.sh` for running PortPeek unattended.

## Commands

| Command | Purpose |
|---|---|
| `add <label> <host>` | Register a new asset under a chosen label |
| `list` | List registered assets |
| `scan <asset>` | Scan an asset and record observations |
| `baseline <asset>` | Accept *all* currently open ports as expected |
| `diff <asset>` | Compare the latest scan against expected state |
| `accept <asset> <port>` | Approve a single port as expected |
| `history <asset>` | Show scan history (optionally for one port) |
| `remove <asset>` | Remove an asset and all its recorded data |
| `cleanup` | Prune old scan history beyond a retention window |
| `version` | Print the PortPeek version |
| `help` | Show usage |

Flags may be given before or after positional arguments — both
`portpeek scan demo-host --ports 22,80` and
`portpeek scan --ports 22,80 demo-host` work.

### `add <label> <host>`

Registers an asset. `<label>` is a name you choose (not the IP) — this is
deliberate: labels stay stable across DHCP changes, and PortPeek's schema
reserves room for future identity evidence (MAC address, TLS certificate
fingerprint, SSH host key fingerprint, mDNS identity) to eventually
corroborate that "home-server" is still the same physical machine even if
its IP moves.

```console
$ portpeek add home-server 192.168.1.50
Added asset "home-server" -> 192.168.1.50
Next: portpeek scan home-server
```

### `list`

Lists registered assets. Supports `--json`.

### `scan <asset>`

Scans the asset's host over TCP connect, records every observation, and
reconciles against expected state.

Flags:

- `--ports SPEC` — e.g. `22,80,443` or `1-1000` or `22,80,8000-8100`.
  Defaults to a curated list of ~30 commonly-relevant ports (not an
  attempt at Nmap's "top 1000" — see [Limitations](#limitations)).
- `--timeout MS` — per-port connect/probe timeout in milliseconds
  (default `1200`).
- `--json` — print a structured result instead of the human-readable view.
- `--quiet` — suppress the port table; print only the final summary.
- `--no-save` — perform the scan but don't persist it or evaluate drift
  (useful for a quick, throwaway look).

### `baseline <asset>`

Accepts every currently-open port from the asset's most recent scan as
expected state, in bulk. Any active `NEW_PORT` events for those ports are
marked accepted.

### `diff <asset>`

Shows confirmed and pending drift for an asset without performing a new
scan — just comparing the already-recorded latest scan against expected
state. Sets the same [exit codes](#exit-codes) as `scan`.

### `accept <asset> <port>`

Approves a single port as expected, with an optional note:

```console
$ portpeek accept home-server 8080 --note "dev server, expected"
8080/tcp is now expected on "home-server" (HTTP).
```

Use this when you want to approve one specific finding without baselining
everything else that's currently open.

### `history <asset>`

Shows recorded scan history. With `--port N`, shows only that port's
observation history across scans (newest first).

### `remove <asset>`

Deletes an asset and everything associated with it (scans, observations,
expected state, events) — irreversible.

### `cleanup`

Prunes scan history older than `--retention-days` (default `30`), while
**always preserving each asset's single most recent scan** regardless of
its age — you never lose the ability to see current state. Also removes
old `resolved`/`accepted` events. Pending and confirmed (not yet accepted)
events are never pruned automatically, since they represent drift you
haven't acted on yet.

```console
$ portpeek cleanup --retention-days 30
Cleanup complete: removed 12 old scan(s) and 3 resolved/accepted event(s) older than 30 day(s).
```

## How drift detection works

Every scan's observations are compared against the asset's expected
(baseline/accepted) state. Five kinds of drift are detected:

| Kind | Meaning |
|---|---|
| `NEW_PORT` | An open port with no matching expected entry |
| `PORT_CLOSED` | A port that was confirmed expected-open is no longer open |
| `SERVICE_CHANGED` | An expected port is still open, but a *different, identified* service now responds |
| `SERVICE_DISAPPEARED` | An expected port's previously-identified service is no longer identifiable |
| `EXPECTED_SERVICE_MISSING` | An expected-open port is no longer open at all |

**No single scan declares confirmed drift.** A new finding starts
`pending`. Only if the *same* finding appears again on the next scan does
it become `confirmed`. If it doesn't reappear, the pending finding is
simply dropped — it was noise, not a real change. This two-scan
confirmation exists specifically to avoid alert fatigue from transient
blips (a service restarting mid-scan, a brief firewall change, etc.).

One asymmetry worth knowing: once a `NEW_PORT` has been *confirmed*, if
that port later closes, PortPeek reports the resulting `PORT_CLOSED`
*immediately confirmed* (not pending) — because it's derived from two
already-confirmed facts (a port that passed its own two-scan confirmation
as open, and a fresh scan showing it's no longer open), not from a single
unconfirmed observation.

PortPeek never reports drift for a port it didn't actually scan this time
(e.g. if you ran with a narrower `--ports` range) — an unscanned expected
port is simply left alone, not treated as closed.

See `docs/design.md` for the full reasoning, including a documented
lesson about why "no identified service" has to be compared carefully
(spoiler: it's not a value that can "change" into another value).

## JSON output

Every meaningful command supports `--json`, producing stable, documented
output with no mixed-in terminal decoration:

```console
$ portpeek scan demo-host --ports 2222,8088 --timeout 300 --json --quiet
{
  "asset": "demo-host",
  "target": "127.0.0.1",
  "vantage": "vm",
  "scanner": "portpeek-tcpconnect/0.1.0",
  "started_at": "2026-10-09T07:51:44Z",
  "finished_at": "2026-10-09T07:51:45Z",
  "ports_spec": "2222,8088",
  "saved": true,
  "observations": [
    {
      "port": 2222,
      "protocol": "tcp",
      "state": "open",
      "service": "SSH",
      "version_info": "OpenSSH 9.6",
      "banner": "SSH-2.0-OpenSSH_9.6",
      "confidence": "high",
      "evidence": "SSH identification string exchange"
    },
    {
      "port": 8088,
      "protocol": "tcp",
      "state": "open",
      "service": "HTTP",
      "version_info": "nginx/1.25.3",
      "confidence": "high",
      "evidence": "HTTP response received to HEAD request"
    }
  ]
}
```

`"vantage"` records where the scan was actually run from (the scanning
machine's hostname) — PortPeek never claims something is "publicly
exposed" or describes exposure from a vantage point it didn't actually
observe from.

The JSON types backing this output (`ScanResult`, `DiffResult`,
`AssetJSON`, `ExpectedJSON`, `EventJSON`, `HistoryEntryJSON`) are defined
in `internal/output/output.go` and are the authoritative schema reference.

## Exit codes

Stable and documented, so PortPeek can be used directly in cron, systemd
timers, or CI gates without parsing text:

| Code | Meaning |
|---|---|
| `0` | Clean — no confirmed or pending drift |
| `1` | Confirmed drift exists |
| `2` | Error (bad arguments, database error, etc.) |
| `3` | Pending (unconfirmed) drift exists — nothing confirmed yet |

`scan` and `diff` both set these. See `examples/cron-check.sh` for a
worked example of branching on them.

## Service fingerprinting

PortPeek performs lightweight, **non-destructive** identification on open
ports — reading banners and sending at most one small, protocol-correct
request per probe. It never authenticates, never exploits, never attempts
to extract more than a service identifies on its own.

Covered today: **SSH, HTTP, HTTPS, FTP, SMTP, MySQL/MariaDB, PostgreSQL,
Redis.**

Every identification carries an explicit `confidence` (`high` / `medium`
/ `low`) and `evidence` describing exactly what was observed. When nothing
matches, PortPeek reports `"Unknown TCP service"` rather than guessing —
that's a deliberate, honest "I don't know," not a placeholder bug.

PortPeek **never** reports a vulnerability or a security judgment from a
port being open or from a banner. It reports what it observed. What that
means for your environment is for you to decide.

MySQL, PostgreSQL, and Redis are only actively probed on their
conventional ports (3306, 5432, 6379) — not blindly tried against every
unknown open port — to avoid sending database wire-protocol bytes
speculatively at services that gave no indication they speak that
protocol. See `docs/design.md` for the full reasoning.

## Data storage

Everything lives in a single SQLite database file — no external database
server, no JSON file sprawl. By default:

- `$PORTPEEK_DB`, if set, is used directly (handy for scripting/testing).
- Otherwise `$XDG_DATA_HOME/portpeek/portpeek.db`.
- Otherwise `~/.local/share/portpeek/portpeek.db`.

The schema: `assets`, `scans`, `observations`, `expected`, `events` (see
`internal/storage/storage.go`). `assets` already reserves nullable columns
for future identity evidence (MAC address, certificate fingerprint, SSH
host key fingerprint, mDNS identity) — unpopulated today, but present so a
future release can fill them in without a destructive migration.

## Using PortPeek unattended (cron/systemd/CI)

```cron
# Check every morning at 7am; alert only on confirmed drift.
0 7 * * * PORTPEEK_DB=/home/you/.local/share/portpeek/portpeek.db /usr/local/bin/portpeek scan home-server --quiet || /usr/local/bin/notify-me.sh
```

See `examples/cron-check.sh` for a more complete example that branches on
all four exit codes distinctly (clean / confirmed / error / pending), and
`examples/basic-workflow.sh` for the full interactive walkthrough above as
a runnable script.

## Responsible use

PortPeek performs active network connections to the hosts you tell it to
scan. **Only scan systems you own or have explicit, documented
authorization to assess.** Scanning systems without authorization may be
illegal in your jurisdiction.

PortPeek is deliberately limited to reduce the chance of misuse and to
keep its findings trustworthy:

- No exploitation, no credential attacks, no brute forcing, no
  vulnerability exploitation.
- No stealth or evasion techniques.
- Lightweight, non-destructive fingerprinting only.
- Never claims a vulnerability from an open port or banner alone.
- No automatic network discovery — you tell it what to scan.

See [SECURITY.md](SECURITY.md) for how to report a security issue in
PortPeek itself.

## Limitations

Documented honestly, not as surprises:

- **TCP connect scanning only.** No SYN/stealth scanning, no UDP, no OS
  fingerprinting.
- **No automatic network discovery.** You register assets explicitly;
  PortPeek doesn't sweep a subnet on its own in this release.
- **A curated default port list (~30 ports), not an exhaustive one.** Pass
  `--ports` explicitly for broader coverage.
- **`baseline` doesn't prune stale expected-state entries.** If a port was
  baselined as expected and then permanently removed from your
  infrastructure, its `expected` row remains (and a subsequent scan not
  covering that port simply won't comment on it, per the "never reason
  about unscanned ports" rule — see `docs/design.md`). There's currently
  no command to explicitly un-baseline a port short of `remove`-ing and
  re-`add`-ing the asset.
- **Single-connection SQLite access.** Fine for a single-user CLI tool;
  not designed for concurrent multi-process writers against the same
  database file.
- **No built-in scheduling.** Use cron/systemd/your CI scheduler — see
  [Using PortPeek unattended](#using-portpeek-unattended-cronsystemdci).

## Roadmap

Ideas under consideration, not commitments:

- Importing observations from other non-destructive sources (e.g. Nmap
  XML) into the same storage/diff/events pipeline — the architecture
  already separates "observation source" from "state engine" specifically
  to make this possible later.
- Optional, explicit (never automatic) network discovery as a distinct,
  clearly-labeled command.
- Populating the reserved identity-evidence columns (MAC address,
  certificate fingerprint, SSH host key fingerprint, mDNS identity) to
  help corroborate asset identity across IP changes.
- A command to explicitly remove a single stale `expected` entry without
  removing the whole asset.

## Development

```bash
make build   # build ./bin/portpeek
make test    # go test ./...
make lint    # go vet + gofmt check (+ staticcheck if installed)
make fmt     # gofmt -w .
make install # go install
make clean   # remove ./bin
```

The full test suite is deterministic and runs fully offline (local
`127.0.0.1:0` listeners stand in for real services; no test depends on
external network access). See [CONTRIBUTING.md](CONTRIBUTING.md) for the
project layout, development workflow, and contribution guidelines, and
[docs/design.md](docs/design.md) for the architectural reasoning behind
key decisions.

## License

[MIT](LICENSE) © rithinkrishnakv
