package storage

import (
	"database/sql"
	"errors"
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
