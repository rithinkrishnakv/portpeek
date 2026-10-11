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

**Every event kind is held to exactly the same rule, including
`PORT_CLOSED` — there is no shortcut.** An earlier version of PortPeek had
`PORT_CLOSED` born already `confirmed`, on the theory that it's derived
from two already-confirmed data points (a port that survived its own
two-scan test as open, plus one fresh "not open" reading) and so didn't
need a confirmation cycle of its own. That reasoning had a real flaw: "not
open" is not the same as "closed". A single `filtered` or `timeout`
reading — a dropped packet, a slow host, a transient network hiccup, not
an actual change on the target — was enough to immediately flip a
confirmed `NEW_PORT` exposure straight to a confirmed `PORT_CLOSED` event
and flip the CLI's exit code to 1, with no corroborating second reading at
all. That's exactly the kind of false-positive confirmation this whole
two-scan design exists to prevent.

`PORT_CLOSED` is now held to the identical rule as everything else, with
two changes on top: first, only a **definitively closed** reading (an
actively refused connection) can ever start or advance it —
`filtered`/`timeout` never count as evidence of anything and are silently
ignored, exactly as if that port hadn't been scanned at all this round
(see `internal/diff`'s `Compute` and `internal/events`'s `Reconcile` for
where this is enforced). Second, because "closed" only means something in
contrast to a port's own event history (there's no user-declared baseline
to compare an *unexpected* open port against), `PORT_CLOSED` candidates
can't be computed by the pure `internal/diff` package the way every other
kind is — they're derived fresh each scan inside `internal/events`,
directly from which ports currently have an active, confirmed `NEW_PORT`
exposure (or an already in-progress `PORT_CLOSED` tracking cycle). Once
derived, a `PORT_CLOSED` candidate flows through the exact same
pending → confirmed machinery as any other kind. Only once `PORT_CLOSED`
itself reaches `confirmed` — two consecutive, definitively-closed
readings — is the original `NEW_PORT` event resolved. A `NEW_PORT` that
was still merely *pending* (never confirmed as a real exposure to begin
with) and then closes is simply cancelled outright, the same as any other
unconfirmed finding that disappears before its own confirmation; no
`PORT_CLOSED` event is created for it at all.

The cost of this fix is that a genuine closure now takes one scan longer
to surface than it used to (two closed readings instead of one). That's
the correct trade: a tool whose "confirmed drift" can be produced by a
single dropped packet is not trustworthy, and losing one scan interval of
latency on a real closure is a far smaller cost than a security tool that
cries wolf on ordinary network noise.

## A confirmed event never resolves itself just by staying true

Once a `PORT_CLOSED` event confirms and resolves its originating
`NEW_PORT` event, `PORT_CLOSED` itself is deliberately left `confirmed` -
not auto-resolved - for as long as the port keeps reading closed. This is
not an oversight; it's the same rule every other event kind follows: a
condition that is still true on a later scan simply keeps getting touched
(its `scan_count` and `last_seen` advance), remaining active, confirmed
drift until a human explicitly acts on it via `baseline` or `accept`.
"Confirmed drift" exists specifically to mean "this needs your attention,"
and a tool that silently stopped saying so once a condition became
routine would defeat the purpose - `diff`/`scan`'s exit code 1 should
never quietly go away on its own.

That rule surfaced a real, related bug worth recording: `PORT_CLOSED`
specifically tracks a port that was *never* formally baselined (an
unexpected `NEW_PORT` exposure that later closed on its own) - by
definition, such a port has no `expected` row to remove. `baseline`
originally only swept a port's active events as a side effect of removing
a stale `expected` row, so a never-baselined port's confirmed
`PORT_CLOSED` event was simply unreachable by `baseline` - it had nothing
to remove, so it touched nothing, so the event sat there confirmed
forever with no bulk way to clear it. The fix: `baseline` now acts on
every definitively-closed port it observes, whether or not it has an
existing expectation to remove, reported separately as "removed" (had a
stale entry) versus "acknowledged" (didn't, but its events were still
cleared) - see `cmd_baseline.go` and the README's `baseline` section.

The `accept` command had a sharper version of the same class of bug:
`accept <port>` always recorded the port as expected-*open*, regardless
of what the latest scan actually observed. Once `accept`'s event-sweep was
widened to cover `PORT_CLOSED` as well (so a confirmed closure could be
dismissed via `accept`, the same as `baseline`), accepting a *closed* port
would simultaneously clear its `PORT_CLOSED` event and insert a
contradictory expected-*open* row for a port that was, in fact, closed -
producing a brand-new `EXPECTED_SERVICE_MISSING` finding on the very next
scan for the exact state just accepted. The general lesson, same shape as
the "Unknown TCP service" one below: **widening what a command cleans up
without checking that its other side effects still make sense for every
state that cleanup can apply to is how you manufacture a duplicate
alert.** The fix made `accept` state-aware like `baseline`: a
definitively-closed port gets its stale expectation removed, not a
contradictory one created.

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
