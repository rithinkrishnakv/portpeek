// Package storage is PortPeek's single source of truth. Everything
// PortPeek knows - assets, scans, observations, expected (baseline)
// state, and drift events - lives in one SQLite database file.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// schemaVersion is bumped whenever the on-disk schema changes. It is
// recorded in schema_meta so a given build of PortPeek can tell an empty
// database (never initialized), an older database (needs migrating up),
// and - critically - a *newer* database (written by a later version of
// PortPeek than this one) apart, and treat each correctly. See init()
// below for how each case is handled; in particular, a newer-than-known
// version must never be silently stamped over, which would both discard
// the information that a newer schema exists and risk operating on tables
// or columns this build doesn't know about.
const schemaVersion = 1

// ErrSchemaTooNew is returned by Open when the database's recorded schema
// version is newer than this build of PortPeek understands - e.g. the
// database was last written by a newer PortPeek release and then opened
// with an older binary. PortPeek refuses to touch such a database rather
// than guessing: silently stamping its own (older) version over the
// recorded one would both lose the fact that a newer schema was in use
// and risk corrupting tables or columns this build doesn't know about.
var ErrSchemaTooNew = errors.New("database schema is newer than this version of portpeek understands")

// Store wraps the SQLite connection and exposes PortPeek's data operations.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and
// ensures the schema is initialized.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite only really supports one writer at a time; keeping a single
	// connection avoids "database is locked" surprises from Go's
	// connection pool for a small CLI tool like this.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrations holds the schema changes needed to bring a database up from
// one version to the next, keyed by the version being migrated *to* (so
// migrations[2] is "how to get from schema version 1 to version 2", and
// so on). Every entry must be additive and non-destructive: ALTER TABLE
// ADD COLUMN, CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS,
// backfilling a new nullable column - never DROP or data-discarding
// rewrites. init() applies these in order inside the same transaction as
// the baseline schema statements, so a multi-version-old database upgrades
// through every intermediate step in one Open() call.
//
// There is nothing here yet because schema version 1 is still the only
// version that has ever shipped; this exists so the *next* schema change
// has an established, tested place to go instead of editing the
// CREATE TABLE statements below in place, which would silently skip
// already-initialized databases that need the new column added instead of
// (harmlessly) re-created.
var migrations = map[int][]string{}

func (s *Store) init() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// schema_meta itself must exist before anything else so its recorded
	// version can be read before any other table is touched - this is
	// what lets a too-new database be detected and refused before this
	// build does anything else to it.
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS schema_meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("init schema_meta: %w", err)
	}

	storedVersion := 0 // 0 means "brand-new database, nothing recorded yet"
	var raw string
	err = tx.QueryRow(`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Brand-new database (or one from before schema_meta existed at
		// all) - storedVersion stays 0, proceed to initialize fresh.
	case err != nil:
		return fmt.Errorf("read schema version: %w", err)
	default:
		storedVersion, err = strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("database has an unreadable schema version %q: %w", raw, err)
		}
	}

	if storedVersion > schemaVersion {
		return fmt.Errorf("%w: database is at schema version %d, this build of portpeek only understands up to version %d - upgrade portpeek before opening this database",
			ErrSchemaTooNew, storedVersion, schemaVersion)
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS assets (
			id                       INTEGER PRIMARY KEY AUTOINCREMENT,
			label                    TEXT NOT NULL UNIQUE,
			host                     TEXT NOT NULL,
			created_at               TEXT NOT NULL,
			mac_address              TEXT,
			cert_fingerprint         TEXT,
			ssh_host_key_fingerprint TEXT,
			mdns_identity            TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			started_at  TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			vantage     TEXT NOT NULL,
			scanner     TEXT NOT NULL,
			ports_spec  TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id, started_at)`,
		`CREATE TABLE IF NOT EXISTS observations (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			port         INTEGER NOT NULL,
			proto        TEXT NOT NULL DEFAULT 'tcp',
			state        TEXT NOT NULL,
			service      TEXT,
			version_info TEXT,
			banner       TEXT,
			confidence   TEXT,
			evidence     TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_observations_scan ON observations(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_observations_scan_port ON observations(scan_id, port)`,
		`CREATE TABLE IF NOT EXISTS expected (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			port        INTEGER NOT NULL,
			proto       TEXT NOT NULL DEFAULT 'tcp',
			state       TEXT NOT NULL DEFAULT 'open',
			service     TEXT,
			accepted_at TEXT NOT NULL,
			note        TEXT,
			UNIQUE(asset_id, port, proto)
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			asset_id     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			kind         TEXT NOT NULL,
			port         INTEGER NOT NULL,
			proto        TEXT NOT NULL DEFAULT 'tcp',
			details      TEXT,
			first_seen   TEXT NOT NULL,
			last_seen    TEXT NOT NULL,
			confirmed_at TEXT,
			scan_count   INTEGER NOT NULL DEFAULT 1,
			status       TEXT NOT NULL DEFAULT 'pending'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_asset_status ON events(asset_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_events_asset_port ON events(asset_id, kind, port, proto)`,
	}

	// The baseline CREATE TABLE/INDEX statements are all IF NOT EXISTS,
	// so they are safe and a no-op to re-run against a database that's
	// already at schemaVersion - this covers both storedVersion == 0
	// (brand-new) and storedVersion == schemaVersion (already current) in
	// one pass. A database strictly between versions (storedVersion > 0
	// and < schemaVersion) additionally needs every migration step from
	// storedVersion+1 up to schemaVersion applied, in order, so it picks
	// up any ALTER TABLE/backfill a later version introduced.
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	for v := storedVersion + 1; v <= schemaVersion; v++ {
		for _, stmt := range migrations[v] {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("migrate schema to version %d: %w", v, err)
			}
		}
	}

	if storedVersion != schemaVersion {
		if _, err := tx.Exec(
			`INSERT INTO schema_meta(key, value) VALUES('version', ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			strconv.Itoa(schemaVersion),
		); err != nil {
			return fmt.Errorf("record schema version: %w", err)
		}
	}

	return tx.Commit()
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
