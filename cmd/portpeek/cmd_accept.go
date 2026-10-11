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

	// Pull the most recently observed state and service for this port, if
	// any, so accept records what was actually seen rather than guessing -
	// and, critically, so it can tell a currently-*closed* port apart from
	// an open (or never-scanned/uncertain) one. Blindly recording every
	// accepted port as "expected open" regardless of its real state would
	// be wrong for a port the user is accepting as closed (e.g. one with
	// an active PORT_CLOSED event): it would immediately create a brand
	// new, contradictory EXPECTED_SERVICE_MISSING finding on the very next
	// scan for the exact state the user just accepted - a duplicate alert
	// for something already acknowledged.
	var state string
	var service *string
	if latest, err := st.LatestScan(asset.ID); err == nil {
		if obs, err := st.GetObservations(latest.ID); err == nil {
			for _, o := range obs {
				if o.Port == port && o.Proto == "tcp" {
					state = o.State
					service = o.Service
					break
				}
			}
		}
	}

	if state == storage.StateClosed {
		// The port is definitively closed: accepting it means removing
		// any stale expected-open entry (if one exists) rather than
		// creating a contradictory expected-open one, and clearing every
		// active event for the port (PORT_CLOSED above all) in the same
		// atomic step - exactly the same state-aware, transactional path
		// `baseline` uses for a closed port with an existing expectation.
		if _, err := st.ApplyBaseline(asset.ID, []storage.BaselineUpdate{
			{Port: port, Proto: "tcp", Remove: true},
		}); err != nil {
			errorf("accept port %d: %v", port, err)
			return ExitError
		}
		if *jsonOut {
			return writeJSONOrErr(struct {
				Port   int    `json:"port"`
				State  string `json:"state"`
				Note   string `json:"note,omitempty"`
				Status string `json:"status"`
			}{Port: port, State: "closed", Status: "accepted"})
		}
		fmt.Printf("%d/tcp is now accepted as closed on %q; any active drift for it is cleared.\n", port, label)
		return ExitClean
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

	// Accept any other active event of any kind for this port - not just
	// NEW_PORT - so approving it as expected-open also clears, say, a
	// still-active SERVICE_CHANGED or EXPECTED_SERVICE_MISSING event for
	// the same port in one step. (PORT_CLOSED is included for
	// completeness/symmetry with `baseline`, though in practice a port
	// reaching this branch was just observed open, so it won't normally
	// have one active.)
	for _, kind := range storage.AllEventKinds {
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
