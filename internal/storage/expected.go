package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Expected is one port the user has explicitly approved as part of an
// asset's normal, expected network footprint - either via `baseline`
// (bulk) or `accept` (single port).
type Expected struct {
	ID         int64
	AssetID    int64
	Port       int
	Proto      string
	State      string
	Service    *string
	AcceptedAt time.Time
	Note       *string
}

// UpsertExpected records (or updates) a single expected port for an asset.
func (s *Store) UpsertExpected(assetID int64, port int, proto, state string, service, note *string) (Expected, error) {
	_, err := s.db.Exec(
		`INSERT INTO expected(asset_id, port, proto, state, service, accepted_at, note)
		 VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(asset_id, port, proto) DO UPDATE SET
		   state = excluded.state,
		   service = excluded.service,
		   accepted_at = excluded.accepted_at,
		   note = excluded.note`,
		assetID, port, proto, state, service, now(), note,
	)
	if err != nil {
		return Expected{}, err
	}
	return s.GetExpected(assetID, port, proto)
}

// GetExpected looks up a single expected-state row.
func (s *Store) GetExpected(assetID int64, port int, proto string) (Expected, error) {
	row := s.db.QueryRow(
		`SELECT id, asset_id, port, proto, state, service, accepted_at, note
		 FROM expected WHERE asset_id = ? AND port = ? AND proto = ?`,
		assetID, port, proto,
	)
	return scanExpectedRow(row)
}

// ListExpected returns every expected-state row for an asset, ordered by
// port.
func (s *Store) ListExpected(assetID int64) ([]Expected, error) {
	rows, err := s.db.Query(
		`SELECT id, asset_id, port, proto, state, service, accepted_at, note
		 FROM expected WHERE asset_id = ? ORDER BY port`, assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Expected
	for rows.Next() {
		e, err := scanExpectedRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// BaselineUpdate describes one port's outcome within a single `baseline`
// run: either its current observed state becomes (or remains) the
// expected state (Upsert), or a stale expected-open entry for it is
// removed because the port was definitively observed closed (Remove).
// Exactly one of Upsert/Remove must be set.
type BaselineUpdate struct {
	Port    int
	Proto   string
	Upsert  bool
	Service *string
	Remove  bool
}

// ApplyBaseline atomically applies a set of per-port baseline decisions
// computed by the caller (see cmd/portpeek's cmdBaseline): each update
// either records/refreshes an expected-open entry for a port that is
// currently open, or removes a stale expected-open entry for a port that
// is now definitively closed. For every affected port, it also marks any
// active event of any kind accepted, so a baseline the user just
// confirmed does not go on contributing to a confirmed-drift exit code.
//
// The whole set is applied inside a single database transaction: on any
// error, nothing in updates takes effect - baseline never leaves an
// asset's expected state (or its events) half-updated, which matters
// because a baseline run typically touches many ports in one call.
//
// It returns the up-to-date Expected row for every Upsert update, in the
// same order as updates (Remove entries contribute nothing to the
// result, since there is no longer a row to describe).
func (s *Store) ApplyBaseline(assetID int64, updates []BaselineUpdate) ([]Expected, error) {
	if len(updates) == 0 {
		return nil, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	ts := now()
	var result []Expected

	for _, u := range updates {
		switch {
		case u.Upsert:
			if _, err := tx.Exec(
				`INSERT INTO expected(asset_id, port, proto, state, service, accepted_at, note)
				 VALUES(?, ?, ?, 'open', ?, ?, NULL)
				 ON CONFLICT(asset_id, port, proto) DO UPDATE SET
				   state = 'open',
				   service = excluded.service,
				   accepted_at = excluded.accepted_at,
				   note = NULL`,
				assetID, u.Port, u.Proto, u.Service, ts,
			); err != nil {
				return nil, fmt.Errorf("record expected state for port %d: %w", u.Port, err)
			}
			row := tx.QueryRow(
				`SELECT id, asset_id, port, proto, state, service, accepted_at, note
				 FROM expected WHERE asset_id = ? AND port = ? AND proto = ?`,
				assetID, u.Port, u.Proto,
			)
			e, err := scanExpectedRow(row)
			if err != nil {
				return nil, fmt.Errorf("read back expected state for port %d: %w", u.Port, err)
			}
			result = append(result, e)

		case u.Remove:
			if _, err := tx.Exec(
				`DELETE FROM expected WHERE asset_id = ? AND port = ? AND proto = ?`,
				assetID, u.Port, u.Proto,
			); err != nil {
				return nil, fmt.Errorf("remove stale expected state for port %d: %w", u.Port, err)
			}

		default:
			return nil, fmt.Errorf("invalid baseline update for port %d: neither Upsert nor Remove set", u.Port)
		}

		for _, kind := range AllEventKinds {
			var evID int64
			err := tx.QueryRow(
				`SELECT id FROM events
				 WHERE asset_id = ? AND kind = ? AND port = ? AND proto = ? AND status IN (?, ?)
				 ORDER BY id DESC LIMIT 1`,
				assetID, kind, u.Port, u.Proto, StatusPending, StatusConfirmed,
			).Scan(&evID)
			if errors.Is(err, sql.ErrNoRows) {
				continue // no active event of this kind for this port
			}
			if err != nil {
				return nil, fmt.Errorf("look up %s event for port %d: %w", kind, u.Port, err)
			}
			if _, err := tx.Exec(`UPDATE events SET status = ? WHERE id = ?`, StatusAccepted, evID); err != nil {
				return nil, fmt.Errorf("accept %s event for port %d: %w", kind, u.Port, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func scanExpectedRow(row rowScanner) (Expected, error) {
	var e Expected
	var service, note sql.NullString
	var acceptedAt string
	err := row.Scan(&e.ID, &e.AssetID, &e.Port, &e.Proto, &e.State, &service, &acceptedAt, &note)
	if errors.Is(err, sql.ErrNoRows) {
		return Expected{}, ErrNotFound
	}
	if err != nil {
		return Expected{}, err
	}
	e.Service = nullableString(service)
	e.Note = nullableString(note)
	e.AcceptedAt, _ = time.Parse(time.RFC3339, acceptedAt)
	return e, nil
}
