#!/usr/bin/env bash
# basic-workflow.sh - a walkthrough of PortPeek's core workflow:
# add an asset, scan it twice (so any findings confirm), baseline the
# result as expected, then scan again and show that it's clean.
#
# This script is meant to be read as much as run - it's a narrated tour,
# not a test. It assumes a `portpeek` binary is on your PATH (run
# `make build && make install`, or point PORTPEEK_BIN at the built
# binary).
#
# Only scan systems you own or have explicit permission to assess.

set -euo pipefail

PORTPEEK="${PORTPEEK_BIN:-portpeek}"

# Use an isolated, throwaway database for this walkthrough so it doesn't
# touch your real PortPeek data. Remove this export to use your normal
# database instead.
export PORTPEEK_DB="$(mktemp -d)/portpeek-demo.db"

echo "==> Using scratch database: $PORTPEEK_DB"
echo

echo "==> Registering an asset"
"$PORTPEEK" add demo-host 127.0.0.1
echo

echo "==> Listing assets"
"$PORTPEEK" list
echo

echo "==> First scan (a newly observed open port is only 'pending' until a second scan confirms it)"
"$PORTPEEK" scan demo-host --ports 1-1024 --timeout 500 || true
echo

echo "==> Second scan (consistent findings now confirm)"
"$PORTPEEK" scan demo-host --ports 1-1024 --timeout 500 || true
echo

echo "==> Reviewing what's confirmed"
"$PORTPEEK" diff demo-host || true
echo

echo "==> Accepting the current state as the expected baseline"
"$PORTPEEK" baseline demo-host
echo

echo "==> Scanning again - should now be clean (exit code 0) since nothing changed"
"$PORTPEEK" scan demo-host --ports 1-1024 --timeout 500
echo "Exit code: $?"
echo

echo "==> Scan history for this asset"
"$PORTPEEK" history demo-host
echo

echo "==> Done. Scratch database left at: $PORTPEEK_DB"
