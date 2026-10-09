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

	var baselined []storage.Expected
	for _, o := range obs {
		if o.State != "open" {
			continue
		}
		e, err := st.UpsertExpected(asset.ID, o.Port, o.Proto, "open", o.Service, nil)
		if err != nil {
			errorf("record expected state for port %d: %v", o.Port, err)
			return ExitError
		}
		baselined = append(baselined, e)

		if active, err := st.FindActiveEvent(asset.ID, storage.EventNewPort, o.Port, o.Proto); err == nil {
			if _, err := st.SetEventStatus(active.ID, storage.StatusAccepted); err != nil {
				errorf("update event for port %d: %v", o.Port, err)
				return ExitError
			}
		}
	}

	if *jsonOut {
		out := make([]output.ExpectedJSON, 0, len(baselined))
		for _, e := range baselined {
			out = append(out, expectedToJSON(e))
		}
		return writeJSONOrErr(out)
	}

	fmt.Printf("Baselined %d open port(s) on %q as expected state.\n", len(baselined), label)
	for _, e := range baselined {
		svc := "-"
		if e.Service != nil {
			svc = *e.Service
		}
		fmt.Printf("  %d/%s  %s\n", e.Port, e.Proto, svc)
	}
	return ExitClean
}
