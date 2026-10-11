package storage

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// openRawForTest opens a plain SQL connection to an existing SQLite file
// without going through Store.Open/init - used only to verify, from
// outside PortPeek's own schema-version gate, exactly what a refused
// Open() did or didn't write to the database file.
func openRawForTest(t *testing.T, path string) (*sql.DB, error) {
	t.Helper()
	return sql.Open("sqlite3", path)
}

// TestOpenFreshDatabaseRecordsCurrentSchemaVersion covers the common
// case: opening a brand-new database file stamps it with the current
// schema version.
func TestOpenFreshDatabaseRecordsCurrentSchemaVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "portpeek.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	var stored string
	if err := st.db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&stored); err != nil {
		t.Fatalf("read back schema version: %v", err)
	}
	if stored != "1" {
		t.Fatalf("expected schema version '1' for a fresh database, got %q", stored)
	}
}

// TestOpenReopenAtSameVersionIsNoop ensures opening an already-current
// database a second time behaves identically - no error, no data loss -
// which the basic workflow (every CLI invocation calls Open) depends on
// implicitly, but is worth pinning down directly now that init() does
// more than it used to.
func TestOpenReopenAtSameVersionIsNoop(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "portpeek.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open (1st): %v", err)
	}
	if _, err := st.CreateAsset("srv1", "10.0.0.5"); err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	st.Close()

	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open (2nd): %v", err)
	}
	defer st2.Close()

	a, err := st2.GetAsset("srv1")
	if err != nil {
		t.Fatalf("expected asset to survive reopening the database: %v", err)
	}
	if a.Label != "srv1" {
		t.Fatalf("unexpected asset after reopen: %+v", a)
	}
}

// TestOpenRefusesNewerSchemaVersion is the key regression test: a
// database whose recorded schema version is newer than this build
// understands must be refused outright - specifically, Open must return
// ErrSchemaTooNew and must NOT silently stamp its own (older) version
// number over the recorded one. Before this fix, every Open() call
// unconditionally overwrote schema_meta's version row, which would have
// silently masked exactly this situation (e.g. a database last written by
// a newer PortPeek release, then opened with an older binary after a
// downgrade) and risked the older binary operating on tables/columns it
// doesn't understand.
func TestOpenRefusesNewerSchemaVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "portpeek.db")

	// Create a fresh, current-version database first.
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open (create): %v", err)
	}
	// Simulate a future release having bumped the schema: stamp a version
	// number higher than anything this build knows about.
	if _, err := st.db.Exec(
		`UPDATE schema_meta SET value = ? WHERE key = 'version'`, "999",
	); err != nil {
		t.Fatalf("simulate future schema version: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening with this (older-relative) build must now fail, not
	// silently downgrade the recorded version.
	st2, err := Open(dbPath)
	if err == nil {
		st2.Close()
		t.Fatal("expected Open to refuse a database with a newer-than-known schema version, got nil error")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew, got %v", err)
	}

	// The crucial assertion: the recorded version in the file itself must
	// be untouched. Open a raw connection (bypassing Store.Open/init, which
	// would refuse) to check directly.
	raw, err := openRawForTest(t, dbPath)
	if err != nil {
		t.Fatalf("open raw connection to verify: %v", err)
	}
	defer raw.Close()

	var stillStored string
	if err := raw.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&stillStored); err != nil {
		t.Fatalf("read schema version after refused Open: %v", err)
	}
	if stillStored != "999" {
		t.Fatalf("Open must never overwrite an unrecognized newer schema version, but it changed to %q", stillStored)
	}
}

// TestOpenCorruptSchemaVersionErrorsRatherThanOverwriting covers an
// unreadable (non-numeric) schema_meta version value: this must also be
// treated as a reason to stop and report an error, not a reason to
// silently stamp a fresh version number over whatever was there.
func TestOpenCorruptSchemaVersionErrorsRatherThanOverwriting(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "portpeek.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open (create): %v", err)
	}
	if _, err := st.db.Exec(
		`UPDATE schema_meta SET value = ? WHERE key = 'version'`, "not-a-number",
	); err != nil {
		t.Fatalf("simulate corrupt schema version: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := Open(dbPath)
	if err == nil {
		st2.Close()
		t.Fatal("expected Open to error on an unreadable schema version, got nil error")
	}

	raw, err := openRawForTest(t, dbPath)
	if err != nil {
		t.Fatalf("open raw connection to verify: %v", err)
	}
	defer raw.Close()
	var stillStored string
	if err := raw.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&stillStored); err != nil {
		t.Fatalf("read schema version after refused Open: %v", err)
	}
	if stillStored != "not-a-number" {
		t.Fatalf("Open must never overwrite a corrupt schema version either, but it changed to %q", stillStored)
	}
}
