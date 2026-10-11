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

// checkPublicTargetAllowed is the public-target scan guard shared by every
// command that actually dials a target (currently just `scan`, for both
// its persisted and --no-save paths). It resolves and classifies
// asset.Host and, if any resolved address is not private/loopback,
// refuses to proceed unless the caller has explicitly allowed it - either
// as a standing, persistent opt-out on the asset itself
// (asset.AllowPublicTarget, set via `add --allow-public-target`), or for
// this one invocation only (confirmFlag, set via `scan
// --confirm-public-target`). On refusal it prints an explanatory error
// itself and returns false; callers should return ExitError in that case.
//
// This is deliberately a check performed immediately before scanning,
// using the same resolver behavior the scanner's own dialer will see
// moments later - not a one-time check at `add` time - because a
// hostname's resolution can change between when an asset was added and
// when it is scanned.
func checkPublicTargetAllowed(ctx context.Context, asset storage.Asset, confirmFlag bool) bool {
	if asset.AllowPublicTarget || confirmFlag {
		return true
	}

	c, err := safety.Classify(ctx, asset.Host)
	if err != nil {
		errorf("resolve target %q for safety check: %v", asset.Host, err)
		return false
	}
	if c.AllPrivate {
		return true
	}

	errorf("asset %q (%s) resolves to a non-private address and scanning it has not been confirmed", asset.Label, asset.Host)
	fmt.Fprintln(os.Stderr, "portpeek: refusing to scan a public target without explicit confirmation, to avoid accidentally scanning hosts you don't control.")
	fmt.Fprintln(os.Stderr, "portpeek: to scan this target once, re-run with --confirm-public-target.")
	fmt.Fprintf(os.Stderr, "portpeek: to always allow this asset, run: portpeek allow-public-target %s\n", asset.Label)
	return false
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
