// Package storage is PortPeek's single source of truth. Everything
// PortPeek knows - assets, scans, observations, expected (baseline)
// state, and drift events - lives in one SQLite database file.
package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// schemaVersion is bumped whenever the schema changes. It is recorded in
// schema_meta so future releases can detect and migrate older databases
// without a destructive reset.
const schemaVersion = "1"

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

func (s *Store) init() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
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

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_meta(key, value) VALUES('version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		schemaVersion,
	); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}

	return tx.Commit()
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
