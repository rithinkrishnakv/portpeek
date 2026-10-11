package main

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/events"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// seedScan records one scan's observations directly through storage and
// runs them through events.Reconcile, exactly as `scan` would - without
// needing a real network target. This makes the two-scan confirmation
// lifecycle (pending -> confirmed -> resolved) fully deterministic in
// tests that need to drive it through several rounds.
func seedScan(t *testing.T, st *storage.Store, assetID int64, obs []storage.Observation) events.Summary {
	t.Helper()
	ts := time.Now()
	scan, err := st.CreateScan(assetID, ts, ts, "testhost", "test-scanner/1", "100")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := st.AddObservations(scan.ID, obs); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}
	summary, err := events.Reconcile(st, assetID, obs)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return summary
}

// TestCLI_AcceptClosedPortDoesNotCreateContradictoryExpectation is the
// regression test for the bug this review pass found: `accept` used to
// unconditionally record a port as expected-*open*, regardless of its
// actual latest state. Combined with `accept` now clearing every active
// event kind (including PORT_CLOSED), accepting a port that had just been
// confirmed *closed* would simultaneously clear the PORT_CLOSED event and
// insert a contradictory "expected open" row for a port that was, in
// fact, closed - guaranteeing a brand-new EXPECTED_SERVICE_MISSING
// duplicate alert on the very next scan for the exact condition the user
// just accepted.
func TestCLI_AcceptClosedPortDoesNotCreateContradictoryExpectation(t *testing.T) {
	newTestDB(t)
	dbPath := os.Getenv("PORTPEEK_DB")

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	a, err := st.CreateAsset("target", "10.0.0.9")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	openObs := []storage.Observation{{Port: 100, Proto: "tcp", State: "open", Service: strp("mystery")}}
	closedObs := []storage.Observation{{Port: 100, Proto: "tcp", State: "closed"}}

	seedScan(t, st, a.ID, openObs)
	seedScan(t, st, a.ID, openObs) // NEW_PORT confirms
	seedScan(t, st, a.ID, closedObs)
	sum := seedScan(t, st, a.ID, closedObs) // PORT_CLOSED confirms, NEW_PORT resolves
	if len(sum.Resolved) != 1 {
		t.Fatalf("expected NEW_PORT to resolve on the 2nd closed scan, got %+v", sum)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 1 || active[0].Kind != storage.EventPortClosed || active[0].Status != storage.StatusConfirmed {
		t.Fatalf("expected exactly 1 confirmed PORT_CLOSED event before accept, got %+v", active)
	}
	st.Close()

	// diff must show confirmed drift (the still-active PORT_CLOSED event)
	// before accept runs.
	if _, code := captureStdout(t, func() int { return run([]string{"diff", "target"}) }); code != ExitConfirmedDrift {
		t.Fatalf("diff before accept: expected exit %d, got %d", ExitConfirmedDrift, code)
	}

	out, code := captureStdout(t, func() int { return run([]string{"accept", "target", "100"}) })
	if code != ExitClean {
		t.Fatalf("accept: expected exit 0, got %d\noutput:\n%s", code, out)
	}

	st2, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open (verify): %v", err)
	}

	// The critical assertion: accepting a closed port must NOT create an
	// expected-open row for it.
	if _, err := st2.GetExpected(a.ID, 100, "tcp"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("accept on a closed port must not create an expected-open entry, got err=%v", err)
	}

	activeAfter, err := st2.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(activeAfter) != 0 {
		t.Fatalf("expected 0 active events after accept, got %d: %+v", len(activeAfter), activeAfter)
	}

	// Simulate one more closed scan: because there is no expected-open
	// entry for this port, this must NOT create a brand-new
	// EXPECTED_SERVICE_MISSING event - that would be exactly the kind of
	// duplicate alert this fix exists to prevent.
	sumAfter := seedScan(t, st2, a.ID, closedObs)
	if len(sumAfter.NewlyPending)+len(sumAfter.NewlyConfirmed) != 0 {
		t.Fatalf("expected no new events from a scan matching the already-accepted closed state, got %+v", sumAfter)
	}
	st2.Close()

	if _, code := captureStdout(t, func() int { return run([]string{"diff", "target"}) }); code != ExitClean {
		t.Fatalf("diff after accept: expected exit 0 (clean), got %d", code)
	}
}

// TestCLI_BaselineAcknowledgesNeverBaselinedClosedPort is the baseline-
// command counterpart: a port that was never baselined (so it has no
// `expected` row to remove) can still carry an active, confirmed
// PORT_CLOSED event once its earlier unexpected exposure has closed.
// Before this fix, `baseline` only swept events for ports it found an
// existing expected-open row to remove for, so a never-baselined closed
// port's PORT_CLOSED event was never reachable by baseline at all -
// leaving it confirmed (and contributing to exit code 1) forever with no
// way to clear it in bulk.
func TestCLI_BaselineAcknowledgesNeverBaselinedClosedPort(t *testing.T) {
	newTestDB(t)
	dbPath := os.Getenv("PORTPEEK_DB")

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	a, err := st.CreateAsset("target", "10.0.0.9")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	openObs := []storage.Observation{{Port: 100, Proto: "tcp", State: "open", Service: strp("mystery")}}
	closedObs := []storage.Observation{{Port: 100, Proto: "tcp", State: "closed"}}

	seedScan(t, st, a.ID, openObs)
	seedScan(t, st, a.ID, openObs)
	seedScan(t, st, a.ID, closedObs)
	seedScan(t, st, a.ID, closedObs) // PORT_CLOSED confirms; port 100 was never baselined

	if _, err := st.GetExpected(a.ID, 100, "tcp"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected no expected-state row for a port that was never baselined, got err=%v", err)
	}
	st.Close()

	out, code := captureStdout(t, func() int { return run([]string{"baseline", "target", "--json"}) })
	if code != ExitClean {
		t.Fatalf("baseline: expected exit 0, got %d\noutput:\n%s", code, out)
	}

	var result struct {
		AcknowledgedPorts []int `json:"acknowledged_ports"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal baseline --json: %v (output=%s)", err, out)
	}
	if len(result.AcknowledgedPorts) != 1 || result.AcknowledgedPorts[0] != 100 {
		t.Fatalf("expected acknowledged_ports [100], got %+v", result.AcknowledgedPorts)
	}

	st2, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open (verify): %v", err)
	}
	defer st2.Close()

	active, err := st2.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected the never-baselined port's PORT_CLOSED event to be cleared by baseline, got %+v", active)
	}
}
