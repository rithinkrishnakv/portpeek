package main

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// TestCLI_BaselineStateAwareSemantics is the regression test for
// `baseline`'s corrected behavior (see docs/design.md): it must treat the
// latest saved scan as the state the user is now explicitly accepting,
// but only ever act on ports it has a *definitive* reading for.
//
// The scan here is seeded directly through internal/storage rather than
// run against real network ports, so every state (open/closed/filtered/
// timeout, plus a port the scan never covered at all) is exact and
// deterministic rather than depending on real connection timing.
func TestCLI_BaselineStateAwareSemantics(t *testing.T) {
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

	// Pre-existing expected state, one entry per scenario this test
	// exercises:
	//   100: no pre-existing expectation (brand-new open port)
	//   200: expected open, now observed definitively closed -> stale,
	//        must be removed
	//   300: expected open, now observed filtered -> uncertain, must
	//        survive untouched
	//   400: expected open, now observed timeout -> uncertain, must
	//        survive untouched
	//   500: expected open, NOT present in this scan at all (a narrower
	//        --ports range) -> must survive untouched
	for _, p := range []int{200, 300, 400, 500} {
		if _, err := st.UpsertExpected(a.ID, p, "tcp", "open", strp("old-svc"), nil); err != nil {
			t.Fatalf("UpsertExpected(%d): %v", p, err)
		}
	}

	ts := time.Now()
	scan, err := st.CreateScan(a.ID, ts, ts, "testhost", "test-scanner/1", "100,200,300,400")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := st.AddObservations(scan.ID, []storage.Observation{
		{Port: 100, Proto: "tcp", State: "open", Service: strp("new-svc")},
		{Port: 200, Proto: "tcp", State: "closed"},
		{Port: 300, Proto: "tcp", State: "filtered"},
		{Port: 400, Proto: "tcp", State: "timeout"},
	}); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}

	// A confirmed NEW_PORT event on the brand-new open port, standing in
	// for what a real `scan` run would have produced by now. Baseline
	// must reconcile this away so a previously-confirmed exposure stops
	// contributing to exit code 1 once the user has explicitly accepted
	// it.
	ev, err := st.CreateEvent(a.ID, storage.EventNewPort, 100, "tcp", strp("first seen"))
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if _, err := st.SetEventStatus(ev.ID, storage.StatusConfirmed); err != nil {
		t.Fatalf("SetEventStatus: %v", err)
	}
	st.Close()

	// Sanity check: diff reports confirmed drift before baseline runs.
	if _, code := captureStdout(t, func() int { return run([]string{"diff", "target"}) }); code != ExitConfirmedDrift {
		t.Fatalf("diff before baseline: expected exit %d (confirmed drift), got %d", ExitConfirmedDrift, code)
	}

	out, code := captureStdout(t, func() int { return run([]string{"baseline", "target"}) })
	if code != ExitClean {
		t.Fatalf("baseline: expected exit 0, got %d\noutput:\n%s", code, out)
	}

	st2, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open (verify): %v", err)
	}
	defer st2.Close()

	// 100: newly baselined open, with the freshly observed service.
	exp100, err := st2.GetExpected(a.ID, 100, "tcp")
	if err != nil {
		t.Fatalf("expected port 100 to be baselined: %v", err)
	}
	if exp100.Service == nil || *exp100.Service != "new-svc" {
		t.Errorf("expected port 100's service to be 'new-svc', got %+v", exp100.Service)
	}

	// 200: stale expectation removed because the port is now definitively
	// closed.
	if _, err := st2.GetExpected(a.ID, 200, "tcp"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected port 200's stale expectation to be removed, got err=%v", err)
	}

	// 300 and 400: uncertain readings (filtered/timeout) must never
	// remove or otherwise touch an existing expectation.
	for _, p := range []int{300, 400} {
		got, err := st2.GetExpected(a.ID, p, "tcp")
		if err != nil {
			t.Errorf("expected port %d's expectation to survive an uncertain (filtered/timeout) reading, got err=%v", p, err)
			continue
		}
		if got.Service == nil || *got.Service != "old-svc" {
			t.Errorf("expected port %d's expectation to be unchanged, got %+v", p, got.Service)
		}
	}

	// 500: outside this scan's port range entirely -> must survive
	// untouched (a partial scan must never erase expectations for ports
	// it didn't look at).
	got500, err := st2.GetExpected(a.ID, 500, "tcp")
	if err != nil {
		t.Errorf("expected port 500's expectation (outside scanned range) to survive, got err=%v", err)
	} else if got500.Service == nil || *got500.Service != "old-svc" {
		t.Errorf("expected port 500's expectation to be unchanged, got %+v", got500.Service)
	}

	// The confirmed NEW_PORT event on port 100 must have been reconciled
	// away by baseline.
	active, err := st2.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("expected 0 active events after baseline, got %d: %+v", len(active), active)
	}

	// diff must now agree there is no drift left.
	if _, code := captureStdout(t, func() int { return run([]string{"diff", "target"}) }); code != ExitClean {
		t.Fatalf("diff after baseline: expected exit 0 (clean), got %d", code)
	}
}

// TestCLI_BaselineJSONReportsRemovedPorts pins down the --json output
// schema for `baseline`: output.BaselineResultJSON, including the
// removed_ports field for stale closed-port entries. This is a breaking
// change from the previous bare-array shape, so the schema itself is
// worth a direct regression test.
func TestCLI_BaselineJSONReportsRemovedPorts(t *testing.T) {
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
	if _, err := st.UpsertExpected(a.ID, 200, "tcp", "open", strp("old-svc"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}
	ts := time.Now()
	scan, err := st.CreateScan(a.ID, ts, ts, "testhost", "test-scanner/1", "100,200")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := st.AddObservations(scan.ID, []storage.Observation{
		{Port: 100, Proto: "tcp", State: "open", Service: strp("new-svc")},
		{Port: 200, Proto: "tcp", State: "closed"},
	}); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}
	st.Close()

	out, code := captureStdout(t, func() int { return run([]string{"baseline", "target", "--json"}) })
	if code != ExitClean {
		t.Fatalf("baseline --json: expected exit 0, got %d\noutput:\n%s", code, out)
	}

	var result output.BaselineResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal baseline --json output: %v (output=%s)", err, out)
	}
	if result.Asset != "target" {
		t.Errorf("expected asset 'target', got %q", result.Asset)
	}
	if len(result.Baselined) != 1 || result.Baselined[0].Port != 100 {
		t.Errorf("expected 1 baselined port (100), got %+v", result.Baselined)
	}
	if len(result.RemovedPorts) != 1 || result.RemovedPorts[0] != 200 {
		t.Errorf("expected removed_ports [200], got %+v", result.RemovedPorts)
	}
}

func strp(s string) *string { return &s }
