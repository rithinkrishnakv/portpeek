#!/usr/bin/env bash
# cron-check.sh - an example of running PortPeek unattended (cron,
# systemd timer, CI job) and branching on its documented exit codes.
#
# PortPeek's `scan` command returns:
#   0 - clean: no confirmed or pending drift
#   1 - confirmed drift: something changed and has been seen on two
#       consecutive scans
#   2 - error: PortPeek itself failed (bad args, DB error, etc.)
#   3 - pending drift: something changed on this scan but hasn't been
#       confirmed yet (needs one more consistent scan)
#
# Wire this into cron/systemd to get alerted only on real, confirmed
# changes, and to distinguish "the target changed" from "PortPeek
# couldn't run" from "something changed once, let's wait and see."
#
# Usage: cron-check.sh <asset-label> [asset-label ...]
#
# Only scan systems you own or have explicit permission to assess.

set -uo pipefail

PORTPEEK="${PORTPEEK_BIN:-portpeek}"

if [ "$#" -eq 0 ]; then
	echo "usage: $0 <asset-label> [asset-label ...]" >&2
	exit 2
fi

overall_status=0

for asset in "$@"; do
	echo "=== $asset ==="

	output="$("$PORTPEEK" scan "$asset" --json --quiet 2>&1)"
	code=$?

	case "$code" in
	0)
		echo "clean"
		;;
	1)
		echo "CONFIRMED DRIFT - see details below"
		echo "$output"
		# Example: pipe a summary to your alerting system of choice here,
		# e.g.:
		#   echo "$output" | mail -s "PortPeek: drift on $asset" ops@example.com
		overall_status=1
		;;
	2)
		echo "ERROR running PortPeek against $asset" >&2
		echo "$output" >&2
		# A hard error (code 2) is distinct from drift (code 1) on
		# purpose - you likely want to alert on this differently (a
		# broken check, not a finding).
		if [ "$overall_status" -eq 0 ]; then
			overall_status=2
		fi
		;;
	3)
		echo "pending drift (unconfirmed) - will resolve on next run"
		if [ "$overall_status" -eq 0 ]; then
			overall_status=3
		fi
		;;
	*)
		echo "unexpected exit code $code" >&2
		overall_status=2
		;;
	esac
	echo
done

exit "$overall_status"
