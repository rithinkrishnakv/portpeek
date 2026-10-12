package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/config"
	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/safety"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// reorderArgs lets flags and positional arguments be given in any order
// (e.g. "portpeek scan home-server --ports 22,80"), which users naturally
// expect but Go's flag package does not support on its own: flag.Parse
// stops consuming flags at the first non-flag token. reorderArgs moves
// every recognized flag (and, for non-boolean flags, its value) to the
// front, preserving relative order, and leaves everything else - the
// positional arguments - in place at the end.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flagsPart, positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]

		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}

		flagsPart = append(flagsPart, a)
		name := strings.TrimLeft(a, "-")
		if strings.ContainsRune(name, '=') {
			// Value is embedded (--flag=value); nothing more to consume.
			continue
		}

		fl := fs.Lookup(name)
		if fl == nil {
			continue
		}
		if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		// Non-boolean flag: its value is the next token, if any.
		if i+1 < len(args) {
			flagsPart = append(flagsPart, args[i+1])
			i++
		}
	}

	return append(flagsPart, positional...)
}

// openStore resolves the configured database path and opens it. Returns
// nil and prints an error on failure; callers should return ExitError.
func openStore() (*storage.Store, bool) {
	path, err := config.DBPath()
	if err != nil {
		errorf("resolve database path: %v", err)
		return nil, false
	}
	st, err := storage.Open(path)
	if err != nil {
		errorf("open database: %v", err)
		return nil, false
	}
	return st, true
}

func errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "portpeek: error: "+format+"\n", args...)
}

func mustAsset(st *storage.Store, label string) (storage.Asset, bool) {
	a, err := st.GetAsset(label)
	if err != nil {
		if err == storage.ErrNotFound {
			errorf("no such asset %q (try: portpeek list)", label)
		} else {
			errorf("look up asset %q: %v", label, err)
		}
		return storage.Asset{}, false
	}
	return a, true
}

func assetToJSON(a storage.Asset) output.AssetJSON {
	return output.AssetJSON{
		Label:             a.Label,
		Host:              a.Host,
		CreatedAt:         a.CreatedAt.Format(time.RFC3339),
		AllowPublicTarget: a.AllowPublicTarget,
	}
}

// classifyFunc resolves and classifies a scan target's address(es) - see
// internal/safety.Classify, which this defaults to. It exists purely as a
// package-level indirection so tests can substitute a fake, deterministic
// classifier (no real DNS lookups or outbound network access, and
// deterministic resolved addresses for the DNS-resolution-consistency
// regression tests - see cmd_public_target_test.go) when testing
// resolveScanTarget's and cmd_scan's decision/wiring logic in isolation.
// It is never overridden or made configurable at runtime by any flag,
// environment variable, or user input - the production `portpeek` binary
// always uses safety.Classify - so this changes nothing about production
// behavior, only what a test build can substitute.
var classifyFunc = safety.Classify

// resolveScanTarget resolves and classifies asset.Host exactly once (via
// classifyFunc, which is safety.Classify in production) and returns the
// single literal address every connection made during this scan
// invocation must actually be dialed to - scanner.Scan and
// fingerprint.Identify are both given this same resolved dialAddr rather
// than asset.Host, so neither re-resolves the hostname on its own.
//
// This single-resolution design is what keeps the address actually
// scanned consistent with the address the public-target safety gate
// evaluated: resolving separately at classify-time and dial-time (the
// previous behavior - this function decided allow/refuse, then handed the
// original hostname to the scanner, which resolved it again itself) left
// a window where a hostname's DNS answer could differ between the two
// resolutions, letting a target classified private at the first
// resolution actually be scanned at a different, possibly public, address
// moments later (or vice versa) - a classic TOCTOU/DNS-rebinding gap. See
// docs/design.md's "DNS resolution consistency" section.
//
// The gate (asset.AllowPublicTarget, confirmFlag, and the classification's
// AllPrivate) is applied the same way as before: refuse unless the
// resolved address(es) are all private/loopback, or the caller has
// explicitly allowed it - either as a standing, persistent opt-out on the
// asset itself (asset.AllowPublicTarget, set via `add
// --allow-public-target`), or for this one invocation only (confirmFlag,
// set via `scan --confirm-public-target`). Resolution happens regardless
// of whether the gate would bypass the check, because every scan needs a
// single, pinned dial address, not just gated ones.
//
// On refusal (including a resolution failure - with no resolved address
// there is no address to safely pin a dial to) it prints an explanatory
// error itself and returns ok=false; callers should return ExitError in
// that case.
func resolveScanTarget(ctx context.Context, asset storage.Asset, confirmFlag bool) (dialAddr string, ok bool) {
	c, err := classifyFunc(ctx, asset.Host)
	if err != nil {
		errorf("resolve target %q: %v", asset.Host, err)
		return "", false
	}
	if len(c.Addrs) == 0 {
		errorf("resolve target %q: no addresses returned", asset.Host)
		return "", false
	}

	if !asset.AllowPublicTarget && !confirmFlag && !c.AllPrivate {
		errorf("asset %q (%s) resolves to a non-private address and scanning it has not been confirmed", asset.Label, asset.Host)
		fmt.Fprintln(os.Stderr, "portpeek: refusing to scan a public target without explicit confirmation, to avoid accidentally scanning hosts you don't control.")
		fmt.Fprintln(os.Stderr, "portpeek: to scan this target once, re-run with --confirm-public-target.")
		fmt.Fprintf(os.Stderr, "portpeek: to always allow this asset, run: portpeek allow-public-target %s\n", asset.Label)
		return "", false
	}

	// Addrs[0] is the first address classifyFunc resolved - the same
	// address (and the same single resolution call) that just decided
	// AllPrivate above, so the gate's decision and the dial target can
	// never disagree. For an asset whose Host is already an IP literal,
	// Classify performs no network resolution at all (a pure parse), so
	// this is exactly asset.Host, unchanged - the single-resolution
	// behavior only matters for hostname-based assets.
	return c.Addrs[0].String(), true
}

func expectedToJSON(e storage.Expected) output.ExpectedJSON {
	out := output.ExpectedJSON{
		Port:       e.Port,
		Protocol:   e.Proto,
		State:      e.State,
		AcceptedAt: e.AcceptedAt.Format(time.RFC3339),
	}
	if e.Service != nil {
		out.Service = *e.Service
	}
	if e.Note != nil {
		out.Note = *e.Note
	}
	return out
}

// writeJSONOrErr writes v as JSON to stdout and returns the matching exit
// code: ExitClean on success, ExitError on a write failure.
func writeJSONOrErr(v any) int {
	if err := output.WriteJSON(os.Stdout, v); err != nil {
		errorf("write JSON output: %v", err)
		return ExitError
	}
	return ExitClean
}
