package events

import (
	"path/filepath"
	"testing"

	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func openTestStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "portpeek.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func strp(s string) *string { return &s }

// TestReconcileNewPortRequiresTwoScans is the central contract of the
// whole event system: a single observation of a new open port must only
// create a *pending* event, never an immediately confirmed one.
func TestReconcileNewPortRequiresTwoScans(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	obs := []storage.Observation{
		{Port: 8080, Proto: "tcp", State: "open", Service: strp("HTTP")},
	}

	// First scan: should produce exactly one newly-pending event.
	sum1, err := Reconcile(st, a.ID, obs)
	if err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	if len(sum1.NewlyPending) != 1 {
		t.Fatalf("expected 1 newly pending event, got %+v", sum1)
	}
	if len(sum1.NewlyConfirmed) != 0 {
		t.Fatalf("a single scan must never confirm an event, got %+v", sum1)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 1 || active[0].Status != storage.StatusPending {
		t.Fatalf("expected 1 pending active event, got %+v", active)
	}

	// Second, consistent scan: the same event should now be confirmed.
	sum2, err := Reconcile(st, a.ID, obs)
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 {
		t.Fatalf("expected 1 newly confirmed event on 2nd consistent scan, got %+v", sum2)
	}
	if len(sum2.NewlyPending) != 0 {
		t.Fatalf("expected no new pending events on 2nd scan, got %+v", sum2)
	}

	active2, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active2) != 1 || active2[0].Status != storage.StatusConfirmed {
		t.Fatalf("expected 1 confirmed active event, got %+v", active2)
	}

	// A third, still-consistent scan should just report "still confirmed".
	sum3, err := Reconcile(st, a.ID, obs)
	if err != nil {
		t.Fatalf("Reconcile (3rd): %v", err)
	}
	if len(sum3.StillConfirmed) != 1 {
		t.Fatalf("expected 1 still-confirmed event on 3rd scan, got %+v", sum3)
	}
	if len(sum3.NewlyConfirmed) != 0 {
		t.Fatalf("event should not be reported newly confirmed twice, got %+v", sum3)
	}
}

// TestReconcileCancelsPendingWhenConditionDisappears covers the
// false-positive-avoidance rule: if a condition that triggered a pending
// event is gone before a second scan confirms it, the pending event must
// be cancelled outright (deleted), not left dangling or confirmed.
func TestReconcileCancelsPendingWhenConditionDisappears(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	// First scan sees a new open port -> pending event.
	sum1, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")},
	})
	if err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	if len(sum1.NewlyPending) != 1 {
		t.Fatalf("expected 1 newly pending event, got %+v", sum1)
	}

	// Second scan: the port is closed again (but still scanned, so we
	// have fresh information about it).
	sum2, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "closed"},
	})
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.Cancelled) != 1 {
		t.Fatalf("expected the pending event to be cancelled, got %+v", sum2)
	}
	if len(sum2.NewlyConfirmed) != 0 {
		t.Fatalf("a cancelled, never-confirmed event must not be reported confirmed, got %+v", sum2)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active events after cancellation, got %+v", active)
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("a cancelled pending event is deleted outright, not just deactivated, got %+v", all)
	}
}

// TestReconcileNeverReasonsAboutUnscannedPorts ensures that an expected
// port simply absent from the current scan's observation set (e.g. a
// narrower --ports range) produces no drift and does not disturb any
// existing active event for that port.
func TestReconcileNeverReasonsAboutUnscannedPorts(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	// A scan that never looked at port 22 at all.
	sum, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 80, Proto: "tcp", State: "open", Service: strp("HTTP")},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Port 80 is new (not in expected), port 22 was not scanned so
	// produces nothing.
	if len(sum.NewlyPending) != 1 {
		t.Fatalf("expected 1 newly pending event for port 80 only, got %+v", sum)
	}
	for _, e := range sum.NewlyPending {
		if e.Port == 22 {
			t.Fatalf("must never create an event for an unscanned expected port")
		}
	}
}

// TestReconcileConfirmedNewPortBecomesPortClosed is the asymmetric
// transition: once a NEW_PORT event is confirmed, if the port later
// closes, PortPeek must immediately record a *confirmed* PORT_CLOSED
// event (skipping its own pending step, since it's derived from two
// already-confirmed data points: a confirmed-open history and a freshly
// scanned closed state) and resolve the old NEW_PORT event.
func TestReconcileConfirmedNewPortBecomesPortClosed(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	openObs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}

	if _, err := Reconcile(st, a.ID, openObs); err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	sum2, err := Reconcile(st, a.ID, openObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 || sum2.NewlyConfirmed[0].Kind != storage.EventNewPort {
		t.Fatalf("expected NEW_PORT to be confirmed by now, got %+v", sum2)
	}
	confirmedNewPortID := sum2.NewlyConfirmed[0].ID

	// Now the port closes.
	sum3, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 22, Proto: "tcp", State: "closed"},
	})
	if err != nil {
		t.Fatalf("Reconcile (3rd): %v", err)
	}
	if len(sum3.NewlyConfirmed) != 1 || sum3.NewlyConfirmed[0].Kind != storage.EventPortClosed {
		t.Fatalf("expected an immediately-confirmed PORT_CLOSED event, got %+v", sum3)
	}
	if sum3.NewlyConfirmed[0].Status != storage.StatusConfirmed {
		t.Fatalf("PORT_CLOSED event must be confirmed immediately, got status %s", sum3.NewlyConfirmed[0].Status)
	}
	if len(sum3.Resolved) != 1 || sum3.Resolved[0].ID != confirmedNewPortID {
		t.Fatalf("expected the old NEW_PORT event to be resolved, got %+v", sum3)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 1 || active[0].Kind != storage.EventPortClosed {
		t.Fatalf("expected exactly 1 active PORT_CLOSED event, got %+v", active)
	}
}

// TestReconcileResolvesConfirmedEventWhenConditionGoesAway covers a
// non-NEW_PORT confirmed event (e.g. SERVICE_CHANGED) whose underlying
// condition disappears - it should be resolved, not deleted, preserving
// history.
func TestReconcileResolvesConfirmedEventWhenConditionGoesAway(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 8080, "tcp", "open", strp("HTTP"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	changedObs := []storage.Observation{
		{Port: 8080, Proto: "tcp", State: "open", Service: strp("Redis")},
	}
	if _, err := Reconcile(st, a.ID, changedObs); err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	sum2, err := Reconcile(st, a.ID, changedObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 || sum2.NewlyConfirmed[0].Kind != storage.EventServiceChanged {
		t.Fatalf("expected confirmed SERVICE_CHANGED, got %+v", sum2)
	}

	// Service reverts back to what was expected.
	sum3, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 8080, Proto: "tcp", State: "open", Service: strp("HTTP")},
	})
	if err != nil {
		t.Fatalf("Reconcile (3rd): %v", err)
	}
	if len(sum3.Resolved) != 1 {
		t.Fatalf("expected the confirmed event to be resolved, got %+v", sum3)
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	found := false
	for _, e := range all {
		if e.Status == storage.StatusResolved {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a resolved event to remain in history, got %+v", all)
	}
}

func TestHasConfirmedAndPendingDrift(t *testing.T) {
	active := []storage.Event{
		{Status: storage.StatusPending},
	}
	if HasConfirmedDrift(active) {
		t.Fatal("expected no confirmed drift")
	}
	if !HasPendingDrift(active) {
		t.Fatal("expected pending drift")
	}

	active = []storage.Event{
		{Status: storage.StatusConfirmed},
	}
	if !HasConfirmedDrift(active) {
		t.Fatal("expected confirmed drift")
	}
	if HasPendingDrift(active) {
		t.Fatal("expected no pending drift")
	}
}
