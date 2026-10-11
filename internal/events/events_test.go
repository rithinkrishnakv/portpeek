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

// TestReconcileConfirmedNewPortBecomesPortClosed covers the NEW_PORT ->
// PORT_CLOSED transition. PORT_CLOSED is held to exactly the same
// two-scan confirmation rule as every other event kind: a single closed
// reading only creates a *pending* PORT_CLOSED event (the original
// NEW_PORT stays confirmed and active throughout), and only a second,
// consistent closed reading confirms it and resolves the NEW_PORT event
// it closes out. There is no shortcut that confirms a closure off one
// scan, however confirmed the prior "open" history was.
func TestReconcileConfirmedNewPortBecomesPortClosed(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	openObs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	closedObs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "closed"},
	}

	if _, err := Reconcile(st, a.ID, openObs); err != nil {
		t.Fatalf("Reconcile (1st, open): %v", err)
	}
	sum2, err := Reconcile(st, a.ID, openObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd, open): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 || sum2.NewlyConfirmed[0].Kind != storage.EventNewPort {
		t.Fatalf("expected NEW_PORT to be confirmed by now, got %+v", sum2)
	}
	confirmedNewPortID := sum2.NewlyConfirmed[0].ID

	// First closed reading: must only create a *pending* PORT_CLOSED
	// event. NEW_PORT must remain confirmed and active - closure is not
	// yet established.
	sum3, err := Reconcile(st, a.ID, closedObs)
	if err != nil {
		t.Fatalf("Reconcile (3rd, closed): %v", err)
	}
	if len(sum3.NewlyPending) != 1 || sum3.NewlyPending[0].Kind != storage.EventPortClosed {
		t.Fatalf("expected a newly *pending* PORT_CLOSED event, got %+v", sum3)
	}
	if len(sum3.NewlyConfirmed) != 0 {
		t.Fatalf("a single closed reading must never confirm PORT_CLOSED, got %+v", sum3)
	}
	if len(sum3.Resolved) != 0 {
		t.Fatalf("NEW_PORT must not be resolved before PORT_CLOSED is confirmed, got %+v", sum3)
	}
	stillActive, err := st.GetEvent(confirmedNewPortID)
	if err != nil {
		t.Fatalf("GetEvent(NEW_PORT): %v", err)
	}
	if stillActive.Status != storage.StatusConfirmed {
		t.Fatalf("expected NEW_PORT to remain confirmed pending PORT_CLOSED's own confirmation, got %s", stillActive.Status)
	}

	// Second, consistent closed reading: PORT_CLOSED confirms, and *only
	// now* is the original NEW_PORT event resolved.
	sum4, err := Reconcile(st, a.ID, closedObs)
	if err != nil {
		t.Fatalf("Reconcile (4th, closed): %v", err)
	}
	if len(sum4.NewlyConfirmed) != 1 || sum4.NewlyConfirmed[0].Kind != storage.EventPortClosed {
		t.Fatalf("expected PORT_CLOSED to confirm on the 2nd consistent closed reading, got %+v", sum4)
	}
	if len(sum4.Resolved) != 1 || sum4.Resolved[0].ID != confirmedNewPortID {
		t.Fatalf("expected the original NEW_PORT event to be resolved now that PORT_CLOSED confirmed, got %+v", sum4)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 1 || active[0].Kind != storage.EventPortClosed || active[0].Status != storage.StatusConfirmed {
		t.Fatalf("expected exactly 1 confirmed active PORT_CLOSED event, got %+v", active)
	}
}

// TestReconcilePendingNewPortClosedBeforeConfirmationIsCancelled checks
// that a NEW_PORT event which never reached confirmed status is simply
// cancelled - not tracked for PORT_CLOSED purposes at all - if its port
// closes before a second open reading can confirm it. There was never a
// confirmed exposure to report the closure of.
func TestReconcilePendingNewPortClosedBeforeConfirmationIsCancelled(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	if _, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")},
	}); err != nil {
		t.Fatalf("Reconcile (1st, open): %v", err)
	}

	sum2, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "closed"},
	})
	if err != nil {
		t.Fatalf("Reconcile (2nd, closed): %v", err)
	}
	if len(sum2.Cancelled) != 1 || sum2.Cancelled[0].Kind != storage.EventNewPort {
		t.Fatalf("expected the never-confirmed NEW_PORT to be cancelled, got %+v", sum2)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active events (no PORT_CLOSED should ever have been created), got %+v", active)
	}
	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected no event history at all - a cancelled pending event is deleted outright, got %+v", all)
	}
}

// --- Uncertain states (filtered/timeout) must never drive drift ----------
//
// These pin down the central correctness requirement of this review: a
// "filtered" or "timeout" reading carries no information and must never
// confirm, cancel, or resolve anything - it must behave exactly as if
// that port had not been scanned at all this round.

// TestReconcileTimeoutNeverConfirmsNewPortClosure: a confirmed NEW_PORT
// exposure that times out on a scan must not start - let alone confirm -
// any PORT_CLOSED tracking. The exposure stays exactly as it was.
func TestReconcileTimeoutNeverConfirmsNewPortClosure(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	openObs := []storage.Observation{{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")}}

	if _, err := Reconcile(st, a.ID, openObs); err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	sum2, err := Reconcile(st, a.ID, openObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 {
		t.Fatalf("expected NEW_PORT confirmed, got %+v", sum2)
	}
	newPortID := sum2.NewlyConfirmed[0].ID

	// Two consecutive timeouts in a row - must change nothing.
	for i := 0; i < 2; i++ {
		sum, err := Reconcile(st, a.ID, []storage.Observation{
			{Port: 22, Proto: "tcp", State: "timeout"},
		})
		if err != nil {
			t.Fatalf("Reconcile (timeout #%d): %v", i, err)
		}
		if len(sum.NewlyPending)+len(sum.NewlyConfirmed)+len(sum.Resolved)+len(sum.Cancelled) != 0 {
			t.Fatalf("a timeout reading must produce no event transitions at all, got %+v", sum)
		}
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 1 || active[0].ID != newPortID || active[0].Kind != storage.EventNewPort || active[0].Status != storage.StatusConfirmed {
		t.Fatalf("expected the original NEW_PORT event untouched, got %+v", active)
	}
}

// TestReconcileFilteredNeverConfirmsExpectedServiceMissing: an expected,
// baselined port that reads "filtered" must never start or advance an
// EXPECTED_SERVICE_MISSING finding, however many scans in a row it stays
// filtered.
func TestReconcileFilteredNeverConfirmsExpectedServiceMissing(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	for i := 0; i < 3; i++ {
		sum, err := Reconcile(st, a.ID, []storage.Observation{
			{Port: 22, Proto: "tcp", State: "filtered"},
		})
		if err != nil {
			t.Fatalf("Reconcile (filtered #%d): %v", i, err)
		}
		if len(sum.NewlyPending) != 0 {
			t.Fatalf("filtered must never create EXPECTED_SERVICE_MISSING, got %+v", sum)
		}
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active events after only filtered readings, got %+v", active)
	}
	if events := mustHasConfirmedOrPendingFalse(t, active); !events {
		t.Fatalf("expected no confirmed or pending drift from filtered readings alone")
	}
}

func mustHasConfirmedOrPendingFalse(t *testing.T, active []storage.Event) bool {
	t.Helper()
	return !HasConfirmedDrift(active) && !HasPendingDrift(active)
}

// TestReconcileOpenTimeoutOpenNeverConfirmsDrift: open, then a transient
// timeout, then open again. Since the timeout reading is simply discarded
// (not "the same meaningful change" twice), and the very next scan shows
// everything is fine again, nothing should ever be flagged.
func TestReconcileOpenTimeoutOpenNeverConfirmsDrift(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	states := []string{"open", "timeout", "open", "filtered", "open"}
	for i, state := range states {
		svc := (*string)(nil)
		if state == "open" {
			svc = strp("SSH")
		}
		sum, err := Reconcile(st, a.ID, []storage.Observation{
			{Port: 22, Proto: "tcp", State: state, Service: svc},
		})
		if err != nil {
			t.Fatalf("Reconcile (#%d, %s): %v", i, state, err)
		}
		if len(sum.NewlyPending) != 0 || len(sum.NewlyConfirmed) != 0 {
			t.Fatalf("alternating open/uncertain readings must never produce drift (step %d, state %s), got %+v", i, state, sum)
		}
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active events, got %+v", active)
	}
}

// TestReconcileGenuinePersistentClosureConfirms is the positive control
// for the tests above: a *real*, repeated closed reading on an expected
// port must still reliably confirm EXPECTED_SERVICE_MISSING on the second
// consistent scan - the uncertain-state handling must not have made
// PortPeek blind to real drift.
func TestReconcileGenuinePersistentClosureConfirms(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	closedObs := []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}}

	sum1, err := Reconcile(st, a.ID, closedObs)
	if err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	if len(sum1.NewlyPending) != 1 || sum1.NewlyPending[0].Kind != storage.EventExpectedServiceMissing {
		t.Fatalf("expected a newly pending EXPECTED_SERVICE_MISSING, got %+v", sum1)
	}

	sum2, err := Reconcile(st, a.ID, closedObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 || sum2.NewlyConfirmed[0].Kind != storage.EventExpectedServiceMissing {
		t.Fatalf("expected EXPECTED_SERVICE_MISSING to confirm on the 2nd consistent closed scan, got %+v", sum2)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if !HasConfirmedDrift(active) {
		t.Fatalf("expected confirmed drift after a genuine persistent closure, got %+v", active)
	}
}

// TestReconcileRecoversAfterTransientFailure: a port that times out mid-
// sequence (right between two otherwise-confirming closed readings) must
// not let the timeout count as, or interrupt, the two-scan confirmation -
// and once the port is seen open again, any pending finding must cancel
// cleanly with no leftover state.
func TestReconcileRecoversAfterTransientFailure(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	// Closed, then a transient timeout (must not reset or confirm
	// anything), then open again (the service was there all along - the
	// pending finding must cancel cleanly).
	sum1, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (closed): %v", err)
	}
	if len(sum1.NewlyPending) != 1 {
		t.Fatalf("expected a newly pending EXPECTED_SERVICE_MISSING, got %+v", sum1)
	}

	sumTimeout, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "timeout"}})
	if err != nil {
		t.Fatalf("Reconcile (timeout): %v", err)
	}
	if len(sumTimeout.NewlyConfirmed) != 0 || len(sumTimeout.Cancelled) != 0 || len(sumTimeout.Resolved) != 0 {
		t.Fatalf("a transient timeout must not confirm, cancel, or resolve anything, got %+v", sumTimeout)
	}

	sumRecover, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	})
	if err != nil {
		t.Fatalf("Reconcile (recovered): %v", err)
	}
	if len(sumRecover.Cancelled) != 1 || sumRecover.Cancelled[0].Kind != storage.EventExpectedServiceMissing {
		t.Fatalf("expected the still-pending EXPECTED_SERVICE_MISSING to cancel on recovery, got %+v", sumRecover)
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected a fully clean slate after recovery, got %+v", active)
	}
}

// TestReconcileNoDuplicateEventsAcrossManyScans runs the same confirmed
// drift condition across many consecutive scans and checks there is still
// exactly one event row for it (touched/refreshed, never duplicated), and
// that it is reported in StillConfirmed - not re-announced as
// NewlyConfirmed - on every scan after the one that actually confirmed it.
func TestReconcileNoDuplicateEventsAcrossManyScans(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	obs := []storage.Observation{{Port: 9999, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")}}

	for i := 0; i < 6; i++ {
		sum, err := Reconcile(st, a.ID, obs)
		if err != nil {
			t.Fatalf("Reconcile (#%d): %v", i, err)
		}
		if i == 0 {
			if len(sum.NewlyPending) != 1 {
				t.Fatalf("scan 0: expected newly pending, got %+v", sum)
			}
		} else if i == 1 {
			if len(sum.NewlyConfirmed) != 1 {
				t.Fatalf("scan 1: expected newly confirmed, got %+v", sum)
			}
		} else {
			if len(sum.NewlyConfirmed) != 0 || len(sum.NewlyPending) != 0 {
				t.Fatalf("scan %d: expected no new announcements, got %+v", i, sum)
			}
			if len(sum.StillConfirmed) != 1 {
				t.Fatalf("scan %d: expected exactly 1 still-confirmed event, got %+v", i, sum)
			}
		}
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 event row after 6 identical scans (touched, never duplicated), got %d: %+v", len(all), all)
	}
	if all[0].ScanCount != 6 {
		t.Fatalf("expected scan_count to reach 6, got %d", all[0].ScanCount)
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

// --- Release-review regression suite: pending-confirmation semantics -----
//
// The six scenarios below are the explicit regression coverage requested
// for the documented rule that an event only confirms after the *same*
// finding is observed on two consecutive scans, and that an uncertain
// ("timeout" or "filtered") reading between two confirming scans pauses
// that streak - it is never treated as a reset, a confirmation, a
// resolution, or a cancellation. Each test checks all four things the
// review asked for: event status, scan_count, the exit code a `scan`
// invocation would produce, and duplicate-event prevention (exactly one
// row per tracked condition, never more, regardless of how many scans ran
// or how many of them were uncertain).

// exitCodeForActive mirrors cmd/portpeek/cmd_scan.go's exitCodeForAsset
// exactly (confirmed drift -> 1, else pending drift -> 3, else clean -> 0
// - see README's documented, stable "Exit codes" contract). It's
// reproduced here, rather than imported, because internal/events cannot
// import package main; it exists so these tests assert the actual exit
// code a real `scan` invocation would produce from a given active-event
// set, not just the lower-level status booleans.
func exitCodeForActive(active []storage.Event) int {
	const (
		exitClean          = 0
		exitConfirmedDrift = 1
		exitPendingDrift   = 3
	)
	if HasConfirmedDrift(active) {
		return exitConfirmedDrift
	}
	if HasPendingDrift(active) {
		return exitPendingDrift
	}
	return exitClean
}

// TestReconcilePendingStreak_ClosedTimeoutClosed_Confirms: closed (pending,
// scan_count 1) -> timeout (must pause: no status/scan_count change, no
// summary transitions at all) -> closed again (confirms, scan_count 2).
// Exactly one EXPECTED_SERVICE_MISSING event row exists throughout.
func TestReconcilePendingStreak_ClosedTimeoutClosed_Confirms(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	// Scan 1: closed -> newly pending, scan_count 1, exit code 3 (pending).
	sum1, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (1st, closed): %v", err)
	}
	if len(sum1.NewlyPending) != 1 || sum1.NewlyPending[0].Kind != storage.EventExpectedServiceMissing {
		t.Fatalf("expected a newly pending EXPECTED_SERVICE_MISSING, got %+v", sum1)
	}
	eventID := sum1.NewlyPending[0].ID
	if sum1.NewlyPending[0].ScanCount != 1 {
		t.Fatalf("expected scan_count 1 after the first reading, got %d", sum1.NewlyPending[0].ScanCount)
	}
	active1, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents (1st): %v", err)
	}
	if got := exitCodeForActive(active1); got != 3 {
		t.Fatalf("expected exit code 3 (pending drift) after 1st scan, got %d", got)
	}

	// Scan 2: timeout -> must pause the streak, not reset or advance it.
	sum2, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "timeout"}})
	if err != nil {
		t.Fatalf("Reconcile (2nd, timeout): %v", err)
	}
	if n := len(sum2.NewlyPending) + len(sum2.NewlyConfirmed) + len(sum2.Resolved) + len(sum2.Cancelled); n != 0 {
		t.Fatalf("a timeout reading must never confirm, resolve, or cancel anything, got %+v", sum2)
	}
	ev, err := st.GetEvent(eventID)
	if err != nil {
		t.Fatalf("GetEvent after timeout: %v", err)
	}
	if ev.Status != storage.StatusPending {
		t.Fatalf("expected the event to remain pending through a timeout, got %s", ev.Status)
	}
	if ev.ScanCount != 1 {
		t.Fatalf("expected scan_count to stay 1 through a timeout (not touched), got %d", ev.ScanCount)
	}
	active2, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents (2nd): %v", err)
	}
	if got := exitCodeForActive(active2); got != 3 {
		t.Fatalf("expected exit code to remain 3 (pending drift) through a timeout, got %d", got)
	}

	// Scan 3: closed again -> the paused streak resumes and confirms.
	sum3, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (3rd, closed): %v", err)
	}
	if len(sum3.NewlyConfirmed) != 1 || sum3.NewlyConfirmed[0].ID != eventID {
		t.Fatalf("expected the same event to confirm on the 3rd scan, got %+v", sum3)
	}
	if sum3.NewlyConfirmed[0].ScanCount != 2 {
		t.Fatalf("expected scan_count 2 at confirmation (the timeout must not have counted), got %d", sum3.NewlyConfirmed[0].ScanCount)
	}
	active3, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents (3rd): %v", err)
	}
	if got := exitCodeForActive(active3); got != 1 {
		t.Fatalf("expected exit code 1 (confirmed drift) after confirmation, got %d", got)
	}

	// Duplicate-event prevention: exactly one row for this condition,
	// across all three scans, timeout included.
	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 event row across closed->timeout->closed, got %d: %+v", len(all), all)
	}
}

// TestReconcilePendingStreak_ClosedFilteredClosed_Confirms is the same
// scenario as above with "filtered" standing in for "timeout" - both are
// uncertain readings and must pause a pending streak identically.
func TestReconcilePendingStreak_ClosedFilteredClosed_Confirms(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	sum1, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (1st, closed): %v", err)
	}
	if len(sum1.NewlyPending) != 1 || sum1.NewlyPending[0].ScanCount != 1 {
		t.Fatalf("expected a newly pending event with scan_count 1, got %+v", sum1)
	}
	eventID := sum1.NewlyPending[0].ID
	active1, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active1); got != 3 {
		t.Fatalf("expected exit code 3 after 1st scan, got %d", got)
	}

	sum2, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "filtered"}})
	if err != nil {
		t.Fatalf("Reconcile (2nd, filtered): %v", err)
	}
	if n := len(sum2.NewlyPending) + len(sum2.NewlyConfirmed) + len(sum2.Resolved) + len(sum2.Cancelled); n != 0 {
		t.Fatalf("a filtered reading must never confirm, resolve, or cancel anything, got %+v", sum2)
	}
	ev, err := st.GetEvent(eventID)
	if err != nil {
		t.Fatalf("GetEvent after filtered: %v", err)
	}
	if ev.Status != storage.StatusPending || ev.ScanCount != 1 {
		t.Fatalf("expected the event untouched (pending, scan_count 1) through a filtered reading, got status=%s scan_count=%d", ev.Status, ev.ScanCount)
	}
	active2, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active2); got != 3 {
		t.Fatalf("expected exit code to remain 3 through a filtered reading, got %d", got)
	}

	sum3, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (3rd, closed): %v", err)
	}
	if len(sum3.NewlyConfirmed) != 1 || sum3.NewlyConfirmed[0].ID != eventID || sum3.NewlyConfirmed[0].ScanCount != 2 {
		t.Fatalf("expected the paused streak to resume and confirm with scan_count 2, got %+v", sum3)
	}
	active3, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active3); got != 1 {
		t.Fatalf("expected exit code 1 (confirmed drift) after confirmation, got %d", got)
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 event row across closed->filtered->closed, got %d: %+v", len(all), all)
	}
}

// TestReconcilePendingStreak_ClosedClosed_ConfirmsOnSecondScan is the
// explicit, fully-checked baseline case with no uncertain reading at all:
// two consecutive closed scans confirm on the second one, with scan_count
// reaching exactly 2 and the exit code moving from pending (3) to
// confirmed (1).
func TestReconcilePendingStreak_ClosedClosed_ConfirmsOnSecondScan(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	sum1, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (1st): %v", err)
	}
	if len(sum1.NewlyPending) != 1 {
		t.Fatalf("expected 1 newly pending event, got %+v", sum1)
	}
	if sum1.NewlyPending[0].Status != storage.StatusPending || sum1.NewlyPending[0].ScanCount != 1 {
		t.Fatalf("expected status=pending scan_count=1 after 1st scan, got %+v", sum1.NewlyPending[0])
	}
	active1, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active1); got != 3 {
		t.Fatalf("expected exit code 3 (pending) after 1st scan, got %d", got)
	}

	sum2, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 {
		t.Fatalf("expected 1 newly confirmed event, got %+v", sum2)
	}
	if sum2.NewlyConfirmed[0].Status != storage.StatusConfirmed || sum2.NewlyConfirmed[0].ScanCount != 2 {
		t.Fatalf("expected status=confirmed scan_count=2 after 2nd scan, got %+v", sum2.NewlyConfirmed[0])
	}
	active2, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active2); got != 1 {
		t.Fatalf("expected exit code 1 (confirmed) after 2nd scan, got %d", got)
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 event row for closed->closed, got %d: %+v", len(all), all)
	}
}

// TestReconcilePendingStreak_ClosedTimeoutOpen_CancelsCleanly: closed
// (pending) -> timeout (paused, untouched) -> open (the condition is
// gone: the still-pending event is cancelled - deleted outright, not
// resolved - and the exit code returns to clean).
func TestReconcilePendingStreak_ClosedTimeoutOpen_CancelsCleanly(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	sum1, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}})
	if err != nil {
		t.Fatalf("Reconcile (1st, closed): %v", err)
	}
	if len(sum1.NewlyPending) != 1 || sum1.NewlyPending[0].ScanCount != 1 {
		t.Fatalf("expected newly pending, scan_count 1, got %+v", sum1)
	}
	active1, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active1); got != 3 {
		t.Fatalf("expected exit code 3 after 1st scan, got %d", got)
	}

	sum2, err := Reconcile(st, a.ID, []storage.Observation{{Port: 22, Proto: "tcp", State: "timeout"}})
	if err != nil {
		t.Fatalf("Reconcile (2nd, timeout): %v", err)
	}
	if n := len(sum2.NewlyPending) + len(sum2.NewlyConfirmed) + len(sum2.Resolved) + len(sum2.Cancelled); n != 0 {
		t.Fatalf("a timeout reading must change nothing, got %+v", sum2)
	}
	active2, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active2); got != 3 {
		t.Fatalf("expected exit code to remain 3 through a timeout, got %d", got)
	}

	sum3, err := Reconcile(st, a.ID, []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	})
	if err != nil {
		t.Fatalf("Reconcile (3rd, open): %v", err)
	}
	if len(sum3.Cancelled) != 1 || sum3.Cancelled[0].Kind != storage.EventExpectedServiceMissing {
		t.Fatalf("expected the still-pending event to cancel on recovery, got %+v", sum3)
	}
	if len(sum3.Resolved) != 0 {
		t.Fatalf("a never-confirmed event must be cancelled, not resolved, got %+v", sum3)
	}
	active3, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents (3rd): %v", err)
	}
	if len(active3) != 0 {
		t.Fatalf("expected no active events after recovery, got %+v", active3)
	}
	if got := exitCodeForActive(active3); got != 0 {
		t.Fatalf("expected exit code 0 (clean) after recovery, got %d", got)
	}

	// Duplicate-event prevention: a cancelled pending event is deleted
	// outright, so no row at all should remain - not a leftover
	// cancelled/duplicate row.
	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected no event rows left after closed->timeout->open, got %d: %+v", len(all), all)
	}
}

// TestReconcileConfirmedDrift_FollowedByTimeout_StaysConfirmedUnchanged
// covers a confirmed, non-NEW_PORT event (SERVICE_CHANGED here) followed
// by a timeout reading: the confirmed finding must survive completely
// unchanged - same status, same scan_count, same exit code - not reset,
// re-confirmed, resolved, or duplicated.
func TestReconcileConfirmedDrift_FollowedByTimeout_StaysConfirmedUnchanged(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 8080, "tcp", "open", strp("HTTP"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	changedObs := []storage.Observation{{Port: 8080, Proto: "tcp", State: "open", Service: strp("Redis")}}

	if _, err := Reconcile(st, a.ID, changedObs); err != nil {
		t.Fatalf("Reconcile (1st, changed): %v", err)
	}
	sum2, err := Reconcile(st, a.ID, changedObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd, changed): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 || sum2.NewlyConfirmed[0].Kind != storage.EventServiceChanged {
		t.Fatalf("expected confirmed SERVICE_CHANGED, got %+v", sum2)
	}
	eventID := sum2.NewlyConfirmed[0].ID
	if sum2.NewlyConfirmed[0].ScanCount != 2 {
		t.Fatalf("expected scan_count 2 at confirmation, got %d", sum2.NewlyConfirmed[0].ScanCount)
	}
	active2, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active2); got != 1 {
		t.Fatalf("expected exit code 1 (confirmed drift) after confirmation, got %d", got)
	}

	// Now a timeout on that same port.
	sum3, err := Reconcile(st, a.ID, []storage.Observation{{Port: 8080, Proto: "tcp", State: "timeout"}})
	if err != nil {
		t.Fatalf("Reconcile (3rd, timeout): %v", err)
	}
	if n := len(sum3.NewlyPending) + len(sum3.NewlyConfirmed) + len(sum3.Resolved) + len(sum3.Cancelled) + len(sum3.StillConfirmed); n != 0 {
		t.Fatalf("a timeout must produce no transitions and not even be reported still-confirmed (it was never touched), got %+v", sum3)
	}

	ev, err := st.GetEvent(eventID)
	if err != nil {
		t.Fatalf("GetEvent after timeout: %v", err)
	}
	if ev.Status != storage.StatusConfirmed {
		t.Fatalf("expected the confirmed event to remain confirmed through a timeout, got %s", ev.Status)
	}
	if ev.ScanCount != 2 {
		t.Fatalf("expected scan_count to stay 2 through a timeout (not touched), got %d", ev.ScanCount)
	}
	active3, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents (3rd): %v", err)
	}
	if !HasConfirmedDrift(active3) {
		t.Fatalf("expected confirmed drift to persist through a timeout, got %+v", active3)
	}
	if got := exitCodeForActive(active3); got != 1 {
		t.Fatalf("expected exit code to remain 1 (confirmed drift) through a timeout, got %d", got)
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 event row (confirmed drift followed by timeout), got %d: %+v", len(all), all)
	}
}

// TestReconcileTrackedNewPortClosure_PausesThroughTimeoutThenConfirms
// applies the same closed->timeout->closed pause-then-confirm pattern to
// the derived PORT_CLOSED path for a previously-confirmed NEW_PORT
// exposure: PORT_CLOSED gets its own pending event with its own
// scan_count progression, a timeout between the two closed readings must
// not advance or disturb it (or the still-confirmed, still-active
// NEW_PORT it will eventually resolve), and NEW_PORT only resolves once
// PORT_CLOSED itself confirms on the second consistent closed reading.
func TestReconcileTrackedNewPortClosure_PausesThroughTimeoutThenConfirms(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	openObs := []storage.Observation{{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")}}
	closedObs := []storage.Observation{{Port: 22, Proto: "tcp", State: "closed"}}
	timeoutObs := []storage.Observation{{Port: 22, Proto: "tcp", State: "timeout"}}

	// Two open scans confirm NEW_PORT.
	if _, err := Reconcile(st, a.ID, openObs); err != nil {
		t.Fatalf("Reconcile (1st, open): %v", err)
	}
	sum2, err := Reconcile(st, a.ID, openObs)
	if err != nil {
		t.Fatalf("Reconcile (2nd, open): %v", err)
	}
	if len(sum2.NewlyConfirmed) != 1 || sum2.NewlyConfirmed[0].Kind != storage.EventNewPort {
		t.Fatalf("expected NEW_PORT confirmed, got %+v", sum2)
	}
	newPortID := sum2.NewlyConfirmed[0].ID
	active2, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active2); got != 1 {
		t.Fatalf("expected exit code 1 after NEW_PORT confirms, got %d", got)
	}

	// First closed reading: pending PORT_CLOSED, scan_count 1. NEW_PORT
	// stays confirmed and active throughout - this test does not re-check
	// that in detail since TestReconcileConfirmedNewPortBecomesPortClosed
	// already covers it; the focus here is the timeout pause.
	sum3, err := Reconcile(st, a.ID, closedObs)
	if err != nil {
		t.Fatalf("Reconcile (3rd, closed): %v", err)
	}
	if len(sum3.NewlyPending) != 1 || sum3.NewlyPending[0].Kind != storage.EventPortClosed {
		t.Fatalf("expected newly pending PORT_CLOSED, got %+v", sum3)
	}
	portClosedID := sum3.NewlyPending[0].ID
	if sum3.NewlyPending[0].ScanCount != 1 {
		t.Fatalf("expected PORT_CLOSED scan_count 1, got %d", sum3.NewlyPending[0].ScanCount)
	}
	active3, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active3); got != 1 {
		t.Fatalf("expected exit code 1 (NEW_PORT still confirmed) after 3rd scan, got %d", got)
	}
	totalAfter3, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents (3rd): %v", err)
	}
	if len(totalAfter3) != 2 {
		t.Fatalf("expected exactly 2 event rows (NEW_PORT + PORT_CLOSED) after 3rd scan, got %d: %+v", len(totalAfter3), totalAfter3)
	}

	// Timeout: must pause PORT_CLOSED's streak and leave NEW_PORT
	// completely untouched - no confirmation, resolution, or cancellation
	// of anything, and no new/duplicate event rows.
	sum4, err := Reconcile(st, a.ID, timeoutObs)
	if err != nil {
		t.Fatalf("Reconcile (4th, timeout): %v", err)
	}
	if n := len(sum4.NewlyPending) + len(sum4.NewlyConfirmed) + len(sum4.Resolved) + len(sum4.Cancelled); n != 0 {
		t.Fatalf("a timeout must produce no transitions at all, got %+v", sum4)
	}
	pcAfterTimeout, err := st.GetEvent(portClosedID)
	if err != nil {
		t.Fatalf("GetEvent(PORT_CLOSED) after timeout: %v", err)
	}
	if pcAfterTimeout.Status != storage.StatusPending || pcAfterTimeout.ScanCount != 1 {
		t.Fatalf("expected PORT_CLOSED to stay pending with scan_count 1 through a timeout, got status=%s scan_count=%d", pcAfterTimeout.Status, pcAfterTimeout.ScanCount)
	}
	npAfterTimeout, err := st.GetEvent(newPortID)
	if err != nil {
		t.Fatalf("GetEvent(NEW_PORT) after timeout: %v", err)
	}
	if npAfterTimeout.Status != storage.StatusConfirmed {
		t.Fatalf("expected NEW_PORT to remain confirmed through a timeout on its tracked port, got %s", npAfterTimeout.Status)
	}
	active4, _ := st.ListActiveEvents(a.ID)
	if got := exitCodeForActive(active4); got != 1 {
		t.Fatalf("expected exit code to remain 1 through the timeout, got %d", got)
	}
	totalAfter4, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents (4th): %v", err)
	}
	if len(totalAfter4) != 2 {
		t.Fatalf("expected still exactly 2 event rows after the timeout (no duplicates), got %d: %+v", len(totalAfter4), totalAfter4)
	}

	// Second, consistent closed reading: PORT_CLOSED's paused streak
	// resumes and confirms (scan_count 2), and only now is NEW_PORT
	// resolved.
	sum5, err := Reconcile(st, a.ID, closedObs)
	if err != nil {
		t.Fatalf("Reconcile (5th, closed): %v", err)
	}
	if len(sum5.NewlyConfirmed) != 1 || sum5.NewlyConfirmed[0].ID != portClosedID {
		t.Fatalf("expected PORT_CLOSED to confirm on the 5th scan, got %+v", sum5)
	}
	if sum5.NewlyConfirmed[0].ScanCount != 2 {
		t.Fatalf("expected PORT_CLOSED scan_count 2 at confirmation (the timeout must not have counted), got %d", sum5.NewlyConfirmed[0].ScanCount)
	}
	if len(sum5.Resolved) != 1 || sum5.Resolved[0].ID != newPortID {
		t.Fatalf("expected NEW_PORT to resolve now that PORT_CLOSED confirmed, got %+v", sum5)
	}

	active5, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents (5th): %v", err)
	}
	if len(active5) != 1 || active5[0].ID != portClosedID || active5[0].Status != storage.StatusConfirmed {
		t.Fatalf("expected exactly 1 active event (confirmed PORT_CLOSED), got %+v", active5)
	}
	if got := exitCodeForActive(active5); got != 1 {
		t.Fatalf("expected exit code 1 (confirmed drift) after PORT_CLOSED confirms, got %d", got)
	}

	// Duplicate-event prevention, final check: still exactly 2 rows total
	// (NEW_PORT, now resolved but preserved in history, and the confirmed
	// PORT_CLOSED) across all 5 scans including the timeout.
	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected exactly 2 event rows total across the whole sequence, got %d: %+v", len(all), all)
	}
}
