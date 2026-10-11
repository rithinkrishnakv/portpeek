package storage

import (
	"errors"
	"testing"
)

// TestApplyBaselineUpsertRecordsExpectedState covers the ordinary case: an
// open port becomes (or refreshes) an expected-open entry, and the
// returned Expected slice reflects it.
func TestApplyBaselineUpsertRecordsExpectedState(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	result, err := st.ApplyBaseline(a.ID, []BaselineUpdate{
		{Port: 22, Proto: "tcp", Upsert: true, Service: strp("SSH")},
	})
	if err != nil {
		t.Fatalf("ApplyBaseline: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result row, got %d", len(result))
	}
	if result[0].Port != 22 || result[0].State != "open" {
		t.Fatalf("unexpected result row: %+v", result[0])
	}
	if result[0].Service == nil || *result[0].Service != "SSH" {
		t.Fatalf("expected service SSH, got %+v", result[0].Service)
	}

	list, err := st.ListExpected(a.ID)
	if err != nil {
		t.Fatalf("ListExpected: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 expected row persisted, got %d", len(list))
	}
}

// TestApplyBaselineRemoveDeletesStaleExpectation covers removal: a port
// with an existing expected-open entry that is now definitively observed
// closed must have that stale entry deleted.
func TestApplyBaselineRemoveDeletesStaleExpectation(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 8080, "tcp", "open", strp("web"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	result, err := st.ApplyBaseline(a.ID, []BaselineUpdate{
		{Port: 8080, Proto: "tcp", Remove: true},
	})
	if err != nil {
		t.Fatalf("ApplyBaseline: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("Remove updates should contribute nothing to the result, got %+v", result)
	}

	if _, err := st.GetExpected(a.ID, 8080, "tcp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the stale expected row to be gone, got err=%v", err)
	}
}

// TestApplyBaselineUntouchedPortsSurvive ensures ApplyBaseline only ever
// acts on ports explicitly named in updates: a port with an existing
// expectation that the caller simply never mentions (e.g. because it was
// filtered/timeout, or outside the scanned port range) must still be
// present and unchanged afterward. cmdBaseline is responsible for not
// constructing a BaselineUpdate for such ports in the first place; this
// pins down that ApplyBaseline itself never reaches past what it's told.
func TestApplyBaselineUntouchedPortsSurvive(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	untouched, err := st.UpsertExpected(a.ID, 9090, "tcp", "open", strp("mystery"), nil)
	if err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	if _, err := st.ApplyBaseline(a.ID, []BaselineUpdate{
		{Port: 22, Proto: "tcp", Upsert: true, Service: strp("SSH")},
	}); err != nil {
		t.Fatalf("ApplyBaseline: %v", err)
	}

	got, err := st.GetExpected(a.ID, 9090, "tcp")
	if err != nil {
		t.Fatalf("expected port 9090 to survive untouched: %v", err)
	}
	if got.ID != untouched.ID || got.Service == nil || *got.Service != "mystery" {
		t.Fatalf("expected port 9090's entry to be unchanged, got %+v", got)
	}
}

// TestApplyBaselineEmptyIsNoop mirrors AddObservations' existing
// empty-input convention: calling with no updates at all must succeed and
// do nothing, not error.
func TestApplyBaselineEmptyIsNoop(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	result, err := st.ApplyBaseline(a.ID, nil)
	if err != nil {
		t.Fatalf("ApplyBaseline(nil): %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for empty updates, got %+v", result)
	}
}

// TestApplyBaselineIsTransactional forces a failure partway through a
// multi-update batch (an update that sets neither Upsert nor Remove) and
// asserts that NONE of the preceding, individually-valid updates in the
// same call took effect: baseline must never leave an asset's expected
// state half-updated.
func TestApplyBaselineIsTransactional(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	// Pre-existing state that the (doomed) batch will try to remove.
	if _, err := st.UpsertExpected(a.ID, 8080, "tcp", "open", strp("web"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}

	_, err = st.ApplyBaseline(a.ID, []BaselineUpdate{
		{Port: 22, Proto: "tcp", Upsert: true, Service: strp("SSH")}, // would succeed alone
		{Port: 8080, Proto: "tcp", Remove: true},                     // would succeed alone
		{Port: 9999, Proto: "tcp"},                                   // invalid: neither Upsert nor Remove
	})
	if err == nil {
		t.Fatal("expected ApplyBaseline to fail on the invalid update, got nil error")
	}

	// Port 22 must NOT have been inserted.
	if _, err := st.GetExpected(a.ID, 22, "tcp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected port 22 upsert to have been rolled back, got err=%v", err)
	}
	// Port 8080's pre-existing row must NOT have been removed.
	if _, err := st.GetExpected(a.ID, 8080, "tcp"); err != nil {
		t.Fatalf("expected port 8080's removal to have been rolled back (row should still exist): %v", err)
	}
}

// TestApplyBaselineAcceptsActiveEventsOfAnyKind confirms that touching a
// port via ApplyBaseline clears every active event for that port,
// regardless of kind - including PORT_CLOSED, which earlier, narrower
// per-command kind lists did not cover. Without this, baselining a port
// could leave a stale active event behind that kept contributing to a
// confirmed-drift exit code even after the user explicitly accepted the
// port's current state.
func TestApplyBaselineAcceptsActiveEventsOfAnyKind(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	var created []Event
	for _, kind := range AllEventKinds {
		ev, err := st.CreateEvent(a.ID, kind, 22, "tcp", strp("test"))
		if err != nil {
			t.Fatalf("CreateEvent(%s): %v", kind, err)
		}
		if _, err := st.SetEventStatus(ev.ID, StatusConfirmed); err != nil {
			t.Fatalf("SetEventStatus(%s): %v", kind, err)
		}
		created = append(created, ev)
	}

	if _, err := st.ApplyBaseline(a.ID, []BaselineUpdate{
		{Port: 22, Proto: "tcp", Upsert: true, Service: strp("SSH")},
	}); err != nil {
		t.Fatalf("ApplyBaseline: %v", err)
	}

	for _, ev := range created {
		got, err := st.GetEvent(ev.ID)
		if err != nil {
			t.Fatalf("GetEvent(%d, kind=%s): %v", ev.ID, ev.Kind, err)
		}
		if got.Status != StatusAccepted {
			t.Errorf("event kind %s: expected status %q after baseline, got %q", ev.Kind, StatusAccepted, got.Status)
		}
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active events after baseline accepted all kinds, got %d: %+v", len(active), active)
	}
}

// TestApplyBaselineOnlyAcceptsEventsForTouchedPorts ensures the
// event-acceptance sweep is scoped per-port: an active event on a port
// NOT named in this baseline call must be left alone.
func TestApplyBaselineOnlyAcceptsEventsForTouchedPorts(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	untouchedEv, err := st.CreateEvent(a.ID, EventNewPort, 9999, "tcp", nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if _, err := st.SetEventStatus(untouchedEv.ID, StatusConfirmed); err != nil {
		t.Fatalf("SetEventStatus: %v", err)
	}

	if _, err := st.ApplyBaseline(a.ID, []BaselineUpdate{
		{Port: 22, Proto: "tcp", Upsert: true, Service: strp("SSH")},
	}); err != nil {
		t.Fatalf("ApplyBaseline: %v", err)
	}

	got, err := st.GetEvent(untouchedEv.ID)
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if got.Status != StatusConfirmed {
		t.Fatalf("expected untouched port's event to remain confirmed, got %q", got.Status)
	}
}
