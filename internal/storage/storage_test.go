package storage

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "portpeek.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func strp(s string) *string { return &s }

func TestCreateAndGetAsset(t *testing.T) {
	st := openTestStore(t)

	a, err := st.CreateAsset("home-server", "192.168.1.10")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if a.ID == 0 {
		t.Fatal("expected non-zero asset ID")
	}
	if a.Label != "home-server" || a.Host != "192.168.1.10" {
		t.Fatalf("unexpected asset: %+v", a)
	}
	if a.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	got, err := st.GetAsset("home-server")
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got.ID != a.ID {
		t.Fatalf("GetAsset returned different asset: %+v vs %+v", got, a)
	}

	byID, err := st.GetAssetByID(a.ID)
	if err != nil {
		t.Fatalf("GetAssetByID: %v", err)
	}
	if byID.Label != "home-server" {
		t.Fatalf("GetAssetByID: unexpected label %q", byID.Label)
	}
}

func TestCreateAssetDuplicateLabel(t *testing.T) {
	st := openTestStore(t)

	if _, err := st.CreateAsset("dupe", "10.0.0.1"); err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	_, err := st.CreateAsset("dupe", "10.0.0.2")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestGetAssetNotFound(t *testing.T) {
	st := openTestStore(t)
	_, err := st.GetAsset("does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListAssetsOrderedByLabel(t *testing.T) {
	st := openTestStore(t)
	for _, label := range []string{"zeta", "alpha", "mike"} {
		if _, err := st.CreateAsset(label, "10.0.0.1"); err != nil {
			t.Fatalf("CreateAsset(%s): %v", label, err)
		}
	}

	assets, err := st.ListAssets()
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 assets, got %d", len(assets))
	}
	want := []string{"alpha", "mike", "zeta"}
	for i, a := range assets {
		if a.Label != want[i] {
			t.Errorf("position %d: expected %q, got %q", i, want[i], a.Label)
		}
	}
}

func TestRemoveAssetCascades(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("gone-soon", "10.0.0.1")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	scan, err := st.CreateScan(a.ID, time.Now(), time.Now(), "testhost", "test-scanner/1", "22")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := st.AddObservations(scan.ID, []Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}
	if _, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), nil); err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}
	if _, err := st.CreateEvent(a.ID, EventNewPort, 22, "tcp", nil); err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}

	if err := st.RemoveAsset("gone-soon"); err != nil {
		t.Fatalf("RemoveAsset: %v", err)
	}

	if _, err := st.GetAsset("gone-soon"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected asset to be gone, got err=%v", err)
	}
	if _, err := st.GetScan(scan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cascaded scan to be gone, got err=%v", err)
	}
	obs, err := st.GetObservations(scan.ID)
	if err != nil {
		t.Fatalf("GetObservations: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected cascaded observations to be gone, got %d", len(obs))
	}
	expected, err := st.ListExpected(a.ID)
	if err != nil {
		t.Fatalf("ListExpected: %v", err)
	}
	if len(expected) != 0 {
		t.Fatalf("expected cascaded expected rows to be gone, got %d", len(expected))
	}
	events, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected cascaded events to be gone, got %d", len(events))
	}
}

func TestRemoveAssetNotFound(t *testing.T) {
	st := openTestStore(t)
	err := st.RemoveAsset("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestScanAndObservationsRoundTrip(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	start := time.Now().Add(-time.Second)
	finish := time.Now()
	scan, err := st.CreateScan(a.ID, start, finish, "myhost", "portpeek-tcpconnect/0.1.0", "22,80,443")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	obsIn := []Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH"), VersionInfo: strp("OpenSSH 9.6")},
		{Port: 80, Proto: "tcp", State: "closed"},
		{Port: 443, Proto: "tcp", State: "filtered"},
	}
	if err := st.AddObservations(scan.ID, obsIn); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}

	obsOut, err := st.GetObservations(scan.ID)
	if err != nil {
		t.Fatalf("GetObservations: %v", err)
	}
	if len(obsOut) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obsOut))
	}
	// Ordered by port.
	if obsOut[0].Port != 22 || obsOut[1].Port != 80 || obsOut[2].Port != 443 {
		t.Fatalf("observations not ordered by port: %+v", obsOut)
	}
	if obsOut[0].Service == nil || *obsOut[0].Service != "SSH" {
		t.Errorf("expected service SSH, got %+v", obsOut[0].Service)
	}
}

func TestAddObservationsEmptyIsNoop(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	scan, err := st.CreateScan(a.ID, time.Now(), time.Now(), "h", "s", "22")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := st.AddObservations(scan.ID, nil); err != nil {
		t.Fatalf("AddObservations(nil): %v", err)
	}
}

func TestLatestScanAndListScans(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	base := time.Now().Add(-time.Hour)
	var last Scan
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		sc, err := st.CreateScan(a.ID, ts, ts, "h", "s", "22")
		if err != nil {
			t.Fatalf("CreateScan %d: %v", i, err)
		}
		last = sc
	}

	latest, err := st.LatestScan(a.ID)
	if err != nil {
		t.Fatalf("LatestScan: %v", err)
	}
	if latest.ID != last.ID {
		t.Fatalf("expected latest scan ID %d, got %d", last.ID, latest.ID)
	}

	all, err := st.ListScans(a.ID, 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 scans, got %d", len(all))
	}
	if all[0].ID != last.ID {
		t.Fatalf("expected newest-first ordering, got %+v", all)
	}

	limited, err := st.ListScans(a.ID, 1)
	if err != nil {
		t.Fatalf("ListScans(limit 1): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected 1 scan with limit, got %d", len(limited))
	}
}

func TestObservationsForPort(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	for i := 0; i < 2; i++ {
		ts := time.Now().Add(time.Duration(i) * time.Minute)
		sc, err := st.CreateScan(a.ID, ts, ts, "h", "s", "22")
		if err != nil {
			t.Fatalf("CreateScan: %v", err)
		}
		state := "open"
		if i == 0 {
			state = "closed"
		}
		if err := st.AddObservations(sc.ID, []Observation{
			{Port: 22, Proto: "tcp", State: state},
		}); err != nil {
			t.Fatalf("AddObservations: %v", err)
		}
	}

	obs, scans, err := st.ObservationsForPort(a.ID, 22, 0)
	if err != nil {
		t.Fatalf("ObservationsForPort: %v", err)
	}
	if len(obs) != 2 || len(scans) != 2 {
		t.Fatalf("expected 2 observations/scans, got %d/%d", len(obs), len(scans))
	}
	// Newest first.
	if obs[0].State != "open" {
		t.Errorf("expected newest observation state 'open', got %q", obs[0].State)
	}
}

func TestUpsertExpected(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	e, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH"), strp("first note"))
	if err != nil {
		t.Fatalf("UpsertExpected: %v", err)
	}
	if e.Service == nil || *e.Service != "SSH" {
		t.Fatalf("expected service SSH, got %+v", e.Service)
	}

	// Upsert again should update, not duplicate.
	e2, err := st.UpsertExpected(a.ID, 22, "tcp", "open", strp("SSH-updated"), strp("second note"))
	if err != nil {
		t.Fatalf("UpsertExpected (update): %v", err)
	}
	if e2.ID != e.ID {
		t.Fatalf("expected same row ID on upsert, got %d vs %d", e2.ID, e.ID)
	}
	if e2.Service == nil || *e2.Service != "SSH-updated" {
		t.Fatalf("expected updated service, got %+v", e2.Service)
	}

	list, err := st.ListExpected(a.ID)
	if err != nil {
		t.Fatalf("ListExpected: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly 1 expected row after upsert, got %d", len(list))
	}
}

func TestEventLifecycle(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	ev, err := st.CreateEvent(a.ID, EventNewPort, 8080, "tcp", strp("first seen"))
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if ev.Status != StatusPending {
		t.Fatalf("expected new event to be pending, got %s", ev.Status)
	}
	if ev.ScanCount != 1 {
		t.Fatalf("expected scan_count 1, got %d", ev.ScanCount)
	}

	found, err := st.FindActiveEvent(a.ID, EventNewPort, 8080, "tcp")
	if err != nil {
		t.Fatalf("FindActiveEvent: %v", err)
	}
	if found.ID != ev.ID {
		t.Fatalf("FindActiveEvent returned different event")
	}

	touched, err := st.TouchEvent(ev.ID, strp("second seen"))
	if err != nil {
		t.Fatalf("TouchEvent: %v", err)
	}
	if touched.ScanCount != 2 {
		t.Fatalf("expected scan_count 2 after touch, got %d", touched.ScanCount)
	}

	confirmed, err := st.SetEventStatus(ev.ID, StatusConfirmed)
	if err != nil {
		t.Fatalf("SetEventStatus(confirmed): %v", err)
	}
	if confirmed.Status != StatusConfirmed {
		t.Fatalf("expected confirmed status, got %s", confirmed.Status)
	}
	if confirmed.ConfirmedAt == nil {
		t.Fatal("expected ConfirmedAt to be set after confirming")
	}

	active, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active event, got %d", len(active))
	}

	resolved, err := st.SetEventStatus(ev.ID, StatusResolved)
	if err != nil {
		t.Fatalf("SetEventStatus(resolved): %v", err)
	}
	if resolved.Status != StatusResolved {
		t.Fatalf("expected resolved status, got %s", resolved.Status)
	}

	activeAfter, err := st.ListActiveEvents(a.ID)
	if err != nil {
		t.Fatalf("ListActiveEvents after resolve: %v", err)
	}
	if len(activeAfter) != 0 {
		t.Fatalf("expected 0 active events after resolving, got %d", len(activeAfter))
	}

	all, err := st.ListEvents(a.ID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 event total (resolved still listed), got %d", len(all))
	}
}

func TestDeleteEventCancelsPending(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	ev, err := st.CreateEvent(a.ID, EventNewPort, 9999, "tcp", nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if err := st.DeleteEvent(ev.ID); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	if _, err := st.GetEvent(ev.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteScansOlderThanPreservesLatest(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	old := time.Now().Add(-100 * 24 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	oldScan, err := st.CreateScan(a.ID, old, old, "h", "s", "22")
	if err != nil {
		t.Fatalf("CreateScan(old): %v", err)
	}
	newScan, err := st.CreateScan(a.ID, recent, recent, "h", "s", "22")
	if err != nil {
		t.Fatalf("CreateScan(recent): %v", err)
	}

	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	n, err := st.DeleteScansOlderThan(a.ID, cutoff)
	if err != nil {
		t.Fatalf("DeleteScansOlderThan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 scan deleted, got %d", n)
	}

	if _, err := st.GetScan(oldScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old scan to be deleted")
	}
	if _, err := st.GetScan(newScan.ID); err != nil {
		t.Fatalf("expected recent scan to survive: %v", err)
	}
}

func TestDeleteScansOlderThanPreservesLatestEvenIfOld(t *testing.T) {
	// If every scan an asset has is older than the retention cutoff, the
	// single most recent one must still be preserved - an asset must
	// never be left with zero scan history after cleanup.
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	veryOld := time.Now().Add(-200 * 24 * time.Hour)
	old := time.Now().Add(-100 * 24 * time.Hour)

	if _, err := st.CreateScan(a.ID, veryOld, veryOld, "h", "s", "22"); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	latest, err := st.CreateScan(a.ID, old, old, "h", "s", "22")
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	n, err := st.DeleteScansOlderThan(a.ID, cutoff)
	if err != nil {
		t.Fatalf("DeleteScansOlderThan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 scan deleted (oldest), got %d", n)
	}

	if _, err := st.GetScan(latest.ID); err != nil {
		t.Fatalf("expected the asset's single latest scan to survive: %v", err)
	}
	remaining, err := st.ListScans(a.ID, 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected exactly 1 scan remaining, got %d", len(remaining))
	}
}

func TestCleanupRemovesOldResolvedEventsOnly(t *testing.T) {
	st := openTestStore(t)
	a, err := st.CreateAsset("srv1", "10.0.0.5")
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	ts := time.Now()
	if _, err := st.CreateScan(a.ID, ts, ts, "h", "s", "22"); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	resolvedOld, err := st.CreateEvent(a.ID, EventPortClosed, 21, "tcp", nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if _, err := st.SetEventStatus(resolvedOld.ID, StatusResolved); err != nil {
		t.Fatalf("SetEventStatus: %v", err)
	}
	// Backdate last_seen directly so it falls outside retention.
	if _, err := st.db.Exec(`UPDATE events SET last_seen = ? WHERE id = ?`,
		time.Now().Add(-100*24*time.Hour).Format(time.RFC3339), resolvedOld.ID); err != nil {
		t.Fatalf("backdate event: %v", err)
	}

	pending, err := st.CreateEvent(a.ID, EventNewPort, 9090, "tcp", nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE events SET last_seen = ? WHERE id = ?`,
		time.Now().Add(-100*24*time.Hour).Format(time.RFC3339), pending.ID); err != nil {
		t.Fatalf("backdate event: %v", err)
	}

	report, err := st.Cleanup(30)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if report.EventsDeleted != 1 {
		t.Fatalf("expected 1 event deleted, got %d", report.EventsDeleted)
	}

	if _, err := st.GetEvent(resolvedOld.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old resolved event to be deleted")
	}
	// Pending events, however old, must never be cleaned up automatically.
	if _, err := st.GetEvent(pending.ID); err != nil {
		t.Fatalf("expected old pending event to survive cleanup: %v", err)
	}
}
