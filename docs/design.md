# PortPeek Design Notes

This document explains the *why* behind PortPeek's architecture and a few
specific decisions that aren't obvious from reading the code alone. It's
aimed at contributors and the curious, not end users (see `README.md` for
usage).

## The core principle: the scanner is the input, the state engine is the product

It would be easy to build PortPeek as "a scanner that also remembers the
last result." That's not what this is. The actual product is the
persistent state engine — the ability to say, with confidence, "this is
what changed since you told me what to expect, and here's the evidence."

That principle drives a concrete architectural boundary:

- `internal/scanner` and `internal/fingerprint` *produce* observations.
  They know nothing about SQLite, expected state, or drift.
- `internal/storage` *persists* observations, expected state, and events.
  It knows nothing about how an observation was produced.
- `internal/diff` *compares* a set of observations against a set of
  expected rows and returns candidate drift. It is a pure function —
  no database handle, no network access, no I/O at all. Given the same
  two inputs, it always returns the same output.
- `internal/events` owns the *stateful* two-scan confirmation lifecycle on
  top of `internal/diff`'s pure comparisons.

This separation is what makes it plausible to add a second observation
source later (e.g. importing Nmap XML) without touching the diff/event
engine at all: anything that can produce `storage.Observation` values can
feed the same pipeline. It's also why `internal/diff` has the most
exhaustive unit test coverage in the codebase relative to its size — pure
functions are cheap to test completely, so there's no excuse not to.

## Why two-scan confirmation exists

A single scan is a snapshot, and snapshots lie — a port that's open for a
few seconds during a deploy, a transient firewall blip, a DHCP lease that
moved. If PortPeek screamed "NEW EXPOSURE" on every single-scan blip, two
things would happen: the output would be useless noise, and people would
start ignoring it, which defeats the entire purpose of a changelog tool.

So every candidate drift condition starts `pending`. It only becomes
`confirmed` once the *same* condition is observed on a second, independent
scan. If the condition disappears before that second confirmation, the
pending event is deleted outright — not resolved, not left behind with a
"never mind" status, just gone, because it was never real to begin with.

This creates one deliberate asymmetry: `PORT_CLOSED` is generated already
`confirmed`, skipping its own pending step. That's not an inconsistency —
it's because a `PORT_CLOSED` event is, by construction, derived from two
already-confirmed data points: a port that was *confirmed open* (meaning
it already survived its own two-scan test) and a fresh scan showing it's
no longer open. Making `PORT_CLOSED` go through its own two-scan
confirmation on top of that would mean a confirmed exposure could linger
for two more scans after it's actually gone, which is the wrong failure
mode for a security-relevant tool: better to report a closure promptly
than to stay silent about one.

## The "Unknown TCP service" lesson

This is worth documenting permanently because it was a real bug, caught
late, and the kind of mistake that's easy to reintroduce by accident.

PortPeek's fingerprinting is deliberately conservative (see below), which
means a meaningful fraction of real-world open ports will come back as
`"Unknown TCP service"` rather than a specific identification. That string
is not a real service name — it's PortPeek's honest way of saying "this
port is open, but I don't know what's listening."

The original diff logic compared `expected.Service` against
`observation.Service` as plain strings. That's wrong, because
`"Unknown TCP service"` is not a value that can meaningfully "change" into
another value — it carries no information in the first place. The bug:
baseline a port while it's unidentified → the baseline record stores
`service = "Unknown TCP service"` → every subsequent scan, as long as the
port is *still* unidentified (a perfectly stable, unchanged state!), would
compare `"Unknown TCP service"` against `"Unknown TCP service"`, decide
nothing changed... except an earlier, less careful version of the
comparison treated the *re-observation* of "unknown" as the service
having "disappeared," because it was checking for an exact prior
identification rather than asking "was this ever actually known?"

Concretely, this surfaced as `SERVICE_DISAPPEARED` events firing on every
single scan after baselining an unidentified port — a tool meant to
reduce noise was instead generating permanent, unfixable noise for a
common case (port exists, nobody can tell what it is, nothing is actually
changing).

It was caught by `cmd/portpeek/cli_test.go`'s full-workflow exit-code
tests, *not* by the lower-level `internal/diff` unit tests, because the
original unit tests didn't happen to construct a baseline-then-reobserve
scenario specifically against an *unidentified* service. That's the
practical argument for keeping both layers of tests: pure-function unit
tests catch logic errors in isolation, but end-to-end CLI tests catch
scenarios nobody thought to construct directly.

The fix (`internal/diff/diff.go`'s `isKnownService` helper) reframes the
comparison: before asking "did the service change," first ask "was the
expected service, and is the observed service, actually a *known*
identification at all?" Only when both sides are known identifications
does a mismatch mean `SERVICE_CHANGED`. Only when the expected side was
known and the observed side has become unknown does it mean
`SERVICE_DISAPPEARED`. Two regression tests
(`TestComputeBaselinedUnknownServiceStaysConsistent` and
`TestComputeUnknownServiceBecomingIdentifiedIsNotFlagged`) pin this
behavior down in both directions.

The general lesson: **a "we don't know" value is not a value that can
change into another value.** Any future field with an "unknown" sentinel
(or a nil/empty representation of "no information") needs the same
treatment in comparison logic — compare "is this known" before comparing
"is this the same."

## Why fingerprinting is conservative about what it probes

`internal/fingerprint`'s `fallbackOrder` deliberately excludes MySQL,
PostgreSQL, and Redis from the blind-fallback probe chain that runs
against ports with no port-based hint. Those three are only probed on
their conventional ports (3306, 5432, 6379) or when a caller invokes their
probe function directly.

The reasoning: SSH, FTP, SMTP, HTTP, and HTTPS all either send a banner
unprompted or respond predictably to a universally-understood,
protocol-correct request (an HTTP HEAD, a TLS ClientHello). Sending a
MySQL handshake-response or Redis `PING` to an arbitrary unknown port,
purely speculatively, starts to look less like "politely asking what's
there" and more like active protocol-specific probing against a service
that gave no indication it speaks that protocol. That's a line PortPeek
chooses not to cross by default — it stays firmly in "lightweight,
non-destructive, port-hinted" territory rather than "throw every protocol
we know at every port and see what sticks."

This is the same philosophy behind PortPeek never claiming a vulnerability
from an open port or a banner, and never attempting any form of
authentication, exploitation, or evasion: the tool's credibility depends
on every claim it makes being something it actually, specifically
observed — not an inference, not a guess, not a "probably."

## Why SQLite, and why a single connection

A single SQLite file keeps PortPeek genuinely local-first and dependency-free
— no server process, no separate install step, trivial to back up (it's
one file), trivial to inspect (`sqlite3 portpeek.db`). The schema is
designed so identity-evidence fields (MAC address, cert fingerprint, SSH
host key fingerprint, mDNS identity) exist as nullable columns on `assets`
from day one, even though nothing populates them yet — adding a
non-destructive migration later (filling in a column) is trivial; adding a
new column to a shipped schema always is. Retrofitting identity tracking
without that groundwork would have meant a real migration later.

`Store.Open` calls `db.SetMaxOpenConns(1)`. SQLite supports exactly one
writer at a time regardless of what Go's connection pool thinks, and for a
single-user CLI tool, serializing all access through one connection is
simpler and more predictable than chasing "database is locked" errors
under Go's default pooling behavior. This is a deliberate trade against
theoretical concurrency PortPeek doesn't need: it's a CLI tool invoked by
one user (or one cron job) at a time, not a multi-tenant server.

## Exit codes are a stable contract

`0` / `1` / `2` / `3` (clean / confirmed drift / error / pending drift)
are documented in the README and treated as a stable public interface —
the same way `--json`'s schema is. The entire point of these specific
codes is to make PortPeek usable unattended (cron, systemd timers, CI
gates) where the caller branches on exit status rather than parsing
human-readable text. Changing their meaning in a later release would
silently break every such integration, so any change here is a breaking
change requiring a major version bump and prominent changelog treatment,
not a quiet tweak.
