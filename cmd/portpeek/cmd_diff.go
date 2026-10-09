package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/events"
	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print the diff report as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek diff <asset>")
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

	active, err := st.ListActiveEvents(asset.ID)
	if err != nil {
		errorf("load events: %v", err)
		return ExitError
	}

	var confirmed, pending []storage.Event
	for _, e := range active {
		switch e.Status {
		case storage.StatusConfirmed:
			confirmed = append(confirmed, e)
		case storage.StatusPending:
			pending = append(pending, e)
		}
	}

	code := ExitClean
	switch {
	case events.HasConfirmedDrift(active):
		code = ExitConfirmedDrift
	case events.HasPendingDrift(active):
		code = ExitPendingDrift
	}

	if *jsonOut {
		res := output.DiffResult{
			Asset:          asset.Label,
			Target:         asset.Host,
			ScanID:         latest.ID,
			ScannedAt:      latest.StartedAt.Format(time.RFC3339),
			ConfirmedDrift: eventsToJSONList(confirmed),
			PendingDrift:   eventsToJSONList(pending),
			ExitCode:       code,
		}
		if writeCode := writeJSONOrErr(res); writeCode != ExitClean {
			return writeCode
		}
		return code
	}

	output.PrintDiffHuman(os.Stdout, asset, confirmed, pending)
	return code
}
