package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func cmdBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print the resulting expected state as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek baseline <asset>")
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

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	asset, ok := mustAsset(st, label)
	if !ok {
		return ExitError
	}

	latest, err := st.LatestScan(asset.ID)
	if err != nil {
		if err == storage.ErrNotFound {
			errorf("no scans recorded for %q yet; run: portpeek scan %s", label, label)
		} else {
			errorf("load latest scan: %v", err)
		}
		return ExitError
	}

	obs, err := st.GetObservations(latest.ID)
	if err != nil {
		errorf("load observations: %v", err)
		return ExitError
	}

	existing, err := st.ListExpected(asset.ID)
	if err != nil {
		errorf("load existing expected state: %v", err)
		return ExitError
	}
	hasExpected := make(map[int]bool, len(existing))
	for _, e := range existing {
		hasExpected[e.Port] = true
	}

	// baseline treats the latest scan as the state the user is now
	// explicitly accepting:
	//   - a port observed open becomes (or remains) expected-open, with
	//     whatever service was actually observed.
	//   - a port observed definitively closed always gets a Remove update
	//     (even when it has no existing expected-open entry to remove,
	//     where it's a harmless no-op delete): what matters is that every
	//     definitively-closed port is "touched" for ApplyBaseline's
	//     per-port event-acceptance sweep, so an active event about that
	//     port - above all a confirmed PORT_CLOSED event, which by design
	//     tracks a port that was *never* formally baselined in the first
	//     place - is cleared by accepting the closure, exactly as it is
	//     for a port that did have a stale expected-open entry. Ports with
	//     an actual stale entry removed, versus ports merely acknowledged,
	//     are reported separately below so the removal count stays
	//     accurate.
	//   - a port read as filtered or timeout is left entirely alone:
	//     baseline never acts on an inconclusive result, the same as
	//     scan/diff never do. A port's existing expected entry (or lack
	//     of one) survives an uncertain reading unchanged, and so does any
	//     active event for it - an uncertain reading is never grounds to
	//     clear a confirmed finding either.
	//   - a port not present in this scan at all (a narrower --ports
	//     range) is, likewise, left entirely alone.
	var updates []storage.BaselineUpdate
	var removedPorts []int
	var acknowledgedPorts []int
	for _, o := range obs {
		switch o.State {
		case "open":
			updates = append(updates, storage.BaselineUpdate{
				Port: o.Port, Proto: o.Proto, Upsert: true, Service: o.Service,
			})
		case "closed":
			updates = append(updates, storage.BaselineUpdate{
				Port: o.Port, Proto: o.Proto, Remove: true,
			})
			if hasExpected[o.Port] {
				removedPorts = append(removedPorts, o.Port)
			} else {
				acknowledgedPorts = append(acknowledgedPorts, o.Port)
			}
		}
	}

	baselined, err := st.ApplyBaseline(asset.ID, updates)
	if err != nil {
		errorf("apply baseline: %v", err)
		return ExitError
	}

	if *jsonOut {
		out := make([]output.ExpectedJSON, 0, len(baselined))
		for _, e := range baselined {
			out = append(out, expectedToJSON(e))
		}
		return writeJSONOrErr(output.BaselineResultJSON{
			Asset:             asset.Label,
			Baselined:         out,
			RemovedPorts:      removedPorts,
			AcknowledgedPorts: acknowledgedPorts,
		})
	}

	if len(updates) == 0 {
		fmt.Printf("Baseline for %q already matches the latest scan; nothing to update.\n", label)
		return ExitClean
	}

	fmt.Printf("Baselined %d open port(s) on %q as expected state.\n", len(baselined), label)
	for _, e := range baselined {
		svc := "-"
		if e.Service != nil {
			svc = *e.Service
		}
		fmt.Printf("  %d/%s  %s\n", e.Port, e.Proto, svc)
	}
	if len(removedPorts) > 0 {
		fmt.Printf("Removed %d stale expected entr%s for now-closed port(s):", len(removedPorts), plural(len(removedPorts), "y", "ies"))
		for _, p := range removedPorts {
			fmt.Printf(" %d/tcp", p)
		}
		fmt.Println()
	}
	if len(acknowledgedPorts) > 0 {
		fmt.Printf("Acknowledged %d closed port(s) with no prior expectation (cleared any active drift events for them):", len(acknowledgedPorts))
		for _, p := range acknowledgedPorts {
			fmt.Printf(" %d/tcp", p)
		}
		fmt.Println()
	}
	return ExitClean
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
