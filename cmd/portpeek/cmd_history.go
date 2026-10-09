package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// defaultHistoryLimit bounds how many scans `history` shows by default, so
// the command stays useful (not a raw database dump) without needing an
// extra flag for the common case.
const defaultHistoryLimit = 30

func cmdHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	portFlag := fs.Int("port", 0, "show history for a single port only")
	jsonOut := fs.Bool("json", false, "print history as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek history <asset> [--port N]")
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

	if *portFlag != 0 {
		obs, scans, err := st.ObservationsForPort(asset.ID, *portFlag, defaultHistoryLimit)
		if err != nil {
			errorf("load port history: %v", err)
			return ExitError
		}
		if *jsonOut {
			entries := make([]output.HistoryEntryJSON, 0, len(obs))
			for i := range obs {
				entries = append(entries, output.HistoryEntryJSON{
					ScanID:       scans[i].ID,
					StartedAt:    scans[i].StartedAt.Format(time.RFC3339),
					Vantage:      scans[i].Vantage,
					PortsSpec:    scans[i].PortsSpec,
					Observations: []output.ObservationJSON{output.ObsToJSON(obs[i])},
				})
			}
			return writeJSONOrErr(entries)
		}
		fmt.Printf("History for %s port %d/tcp\n\n", asset.Label, *portFlag)
		if len(obs) == 0 {
			fmt.Println("No history recorded for this port.")
			return ExitClean
		}
		for i, o := range obs {
			svc := "-"
			if o.Service != nil {
				svc = *o.Service
			}
			fmt.Printf("%s  scan #%d  %-8s %s\n",
				scans[i].StartedAt.Format("2006-01-02 15:04:05 MST"), scans[i].ID, o.State, svc)
		}
		return ExitClean
	}

	scans, err := st.ListScans(asset.ID, defaultHistoryLimit)
	if err != nil {
		errorf("load scan history: %v", err)
		return ExitError
	}

	obsByScan := make(map[int64][]storage.Observation, len(scans))
	for _, sc := range scans {
		obs, err := st.GetObservations(sc.ID)
		if err != nil {
			errorf("load observations for scan %d: %v", sc.ID, err)
			return ExitError
		}
		obsByScan[sc.ID] = obs
	}

	if *jsonOut {
		entries := make([]output.HistoryEntryJSON, 0, len(scans))
		for _, sc := range scans {
			entries = append(entries, output.HistoryEntryJSON{
				ScanID:       sc.ID,
				StartedAt:    sc.StartedAt.Format(time.RFC3339),
				Vantage:      sc.Vantage,
				PortsSpec:    sc.PortsSpec,
				Observations: obsToJSONList(obsByScan[sc.ID]),
			})
		}
		return writeJSONOrErr(entries)
	}

	output.PrintHistoryHuman(os.Stdout, asset, scans, obsByScan, 0)
	return ExitClean
}
