package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rithinkrishnakv/portpeek/internal/config"
)

func cmdCleanup(args []string) int {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	retentionDays := fs.Int("retention-days", config.DefaultRetentionDays, "delete scan history older than this many days (each asset's latest scan is always kept)")
	jsonOut := fs.Bool("json", false, "print the cleanup report as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek cleanup [--retention-days N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return ExitError
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return ExitError
	}
	if *retentionDays < 0 {
		errorf("--retention-days must be >= 0")
		return ExitError
	}

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	report, err := st.Cleanup(*retentionDays)
	if err != nil {
		errorf("cleanup: %v", err)
		return ExitError
	}

	if *jsonOut {
		return writeJSONOrErr(struct {
			ScansDeleted  int64 `json:"scans_deleted"`
			EventsDeleted int64 `json:"events_deleted"`
			RetentionDays int   `json:"retention_days"`
		}{report.ScansDeleted, report.EventsDeleted, *retentionDays})
	}

	fmt.Printf("Cleanup complete: removed %d old scan(s) and %d resolved/accepted event(s) older than %d day(s).\n",
		report.ScansDeleted, report.EventsDeleted, *retentionDays)
	return ExitClean
}
