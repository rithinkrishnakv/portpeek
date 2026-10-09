package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func cmdAccept(args []string) int {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	note := fs.String("note", "", "optional note explaining why this port is expected")
	jsonOut := fs.Bool("json", false, "print the resulting expected-state entry as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek accept <asset> <port> [--note \"...\"]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return ExitError
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return ExitError
	}
	label := fs.Arg(0)
	port, err := strconv.Atoi(fs.Arg(1))
	if err != nil || port < 1 || port > 65535 {
		errorf("invalid port %q", fs.Arg(1))
		return ExitError
	}

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	asset, ok := mustAsset(st, label)
	if !ok {
		return ExitError
	}

	// Pull the most recently observed service for this port, if any, so
	// the baseline records what was actually seen rather than guessing.
	var service *string
	if latest, err := st.LatestScan(asset.ID); err == nil {
		if obs, err := st.GetObservations(latest.ID); err == nil {
			for _, o := range obs {
				if o.Port == port && o.Proto == "tcp" {
					service = o.Service
					break
				}
			}
		}
	}

	var notePtr *string
	if *note != "" {
		notePtr = note
	}

	e, err := st.UpsertExpected(asset.ID, port, "tcp", "open", service, notePtr)
	if err != nil {
		errorf("accept port %d: %v", port, err)
		return ExitError
	}

	for _, kind := range []string{
		storage.EventNewPort,
		storage.EventServiceChanged,
		storage.EventServiceDisappeared,
		storage.EventExpectedServiceMissing,
	} {
		if active, err := st.FindActiveEvent(asset.ID, kind, port, "tcp"); err == nil {
			if _, err := st.SetEventStatus(active.ID, storage.StatusAccepted); err != nil {
				errorf("update event: %v", err)
				return ExitError
			}
		}
	}

	if *jsonOut {
		return writeJSONOrErr(expectedToJSON(e))
	}

	svc := "unspecified service"
	if e.Service != nil {
		svc = *e.Service
	}
	fmt.Printf("%d/tcp is now expected on %q (%s).\n", port, label, svc)
	return ExitClean
}
