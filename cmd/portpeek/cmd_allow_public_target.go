package main

import (
	"flag"
	"fmt"
	"os"
)

// cmdAllowPublicTarget sets or clears an existing asset's persistent,
// explicit opt-out of the public-target scan confirmation (see
// internal/safety and checkPublicTargetAllowed in helpers.go). `add
// --allow-public-target` covers this at creation time; this command is
// for an asset that already exists - e.g. one added before its host
// started resolving publicly, or one where the decision is being
// reconsidered.
func cmdAllowPublicTarget(args []string) int {
	fs := flag.NewFlagSet("allow-public-target", flag.ContinueOnError)
	off := fs.Bool("off", false, "revert: require confirmation again for this asset's public targets")
	jsonOut := fs.Bool("json", false, "print the updated asset as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek allow-public-target <asset> [--off]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return ExitError
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return ExitError
	}
	label := fs.Arg(0)
	allow := !*off

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	asset, ok := mustAsset(st, label)
	if !ok {
		return ExitError
	}

	if err := st.SetAllowPublicTarget(asset.ID, allow); err != nil {
		errorf("set allow-public-target for %q: %v", label, err)
		return ExitError
	}
	asset.AllowPublicTarget = allow

	if *jsonOut {
		return writeJSONOrErr(assetToJSON(asset))
	}

	if allow {
		fmt.Printf("%q will no longer require per-scan confirmation for public targets.\n", label)
	} else {
		fmt.Printf("%q will now require confirmation again before scanning a public target.\n", label)
	}
	return ExitClean
}
