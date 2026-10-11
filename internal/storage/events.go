package storage

import (
	"database/sql"
	"errors"
	"time"
)

// Event kinds. Kept as typed string constants so callers in internal/diff
// and internal/events can't typo a kind string.
const (
	EventNewPort                = "NEW_PORT"
	EventPortClosed             = "PORT_CLOSED"
	EventServiceChanged         = "SERVICE_CHANGED"
	EventServiceDisappeared     = "SERVICE_DISAPPEARED"
	EventExpectedServiceMissing = "EXPECTED_SERVICE_MISSING"
)

// AllEventKinds lists every event Kind that exists. `accept` and
// `baseline` both use this to mark every active event for a port
// accepted, regardless of kind, when the user approves that port's
// current state - trying to accept a kind with no active event for that
// port is a harmless no-op, so there is no reason for either command to
// maintain its own narrower, easy-to-forget-to-update list.
var AllEventKinds = []string{
	EventNewPort,
	EventServiceChanged,
	EventServiceDisappeared,
	EventExpectedServiceMissing,
	EventPortClosed,
}

// Event statuses.
const (
	StatusPending   = "pending"
	StatusConfirmed = "confirmed"
	StatusAccepted  = "accepted"
	StatusResolved  = "resolved"
)

// Event is a detected, tracked piece of drift between expected and
// observed state for one (asset, port, proto). It starts life as
// "pending" and only becomes "confirmed" once the same condition has been
// observed across two consecutive scans - see internal/events.
type Event struct {
	ID          int64
	AssetID     int64
	Kind        string
	Port        int
	Proto       string
	Details     *string
	FirstSeen   time.Time
	LastSeen    time.Time
	ConfirmedAt *time.Time
	ScanCount   int
	Status      string
}

// CreateEvent inserts a brand-new pending event.
func (s *Store) CreateEvent(assetID int64, kind string, port int, proto string, details *string) (Event, error) {
	ts := now()
	res, err := s.db.Exec(
		`INSERT INTO events(asset_id, kind, port, proto, details, first_seen, last_seen, scan_count, status)
		 VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		assetID, kind, port, proto, details, ts, ts, StatusPending,
	)
	if err != nil {
		return Event{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Event{}, err
	}
	return s.GetEvent(id)
}

// GetEvent looks up an event by ID.
func (s *Store) GetEvent(id int64) (Event, error) {
	row := s.db.QueryRow(
		`SELECT id, asset_id, kind, port, proto, details, first_seen, last_seen, confirmed_at, scan_count, status
		 FROM events WHERE id = ?`, id,
	)
	return scanEventRow(row)
}

// FindActiveEvent looks for an existing pending or confirmed event for the
// given (asset, kind, port, proto).
func (s *Store) FindActiveEvent(assetID int64, kind string, port int, proto string) (Event, error) {
	row := s.db.QueryRow(
		`SELECT id, asset_id, kind, port, proto, details, first_seen, last_seen, confirmed_at, scan_count, status
		 FROM events
		 WHERE asset_id = ? AND kind = ? AND port = ? AND proto = ? AND status IN ('pending','confirmed')
		 ORDER BY id DESC LIMIT 1`,
		assetID, kind, port, proto,
	)
	return scanEventRow(row)
}

// TouchEvent advances an existing event's last_seen timestamp and
// increments its scan_count, recording the latest details. It does not
// change status - that is a policy decision made by internal/events.
func (s *Store) TouchEvent(id int64, details *string) (Event, error) {
	_, err := s.db.Exec(
		`UPDATE events SET last_seen = ?, scan_count = scan_count + 1, details = ? WHERE id = ?`,
		now(), details, id,
	)
	if err != nil {
		return Event{}, err
	}
	return s.GetEvent(id)
}

// SetEventStatus transitions an event to a new status. When status is
// "confirmed", confirmed_at is stamped with the current time.
func (s *Store) SetEventStatus(id int64, status string) (Event, error) {
	if status == StatusConfirmed {
		_, err := s.db.Exec(`UPDATE events SET status = ?, confirmed_at = ? WHERE id = ?`, status, now(), id)
		if err != nil {
			return Event{}, err
		}
	} else {
		_, err := s.db.Exec(`UPDATE events SET status = ? WHERE id = ?`, status, id)
		if err != nil {
			return Event{}, err
		}
	}
	return s.GetEvent(id)
}

// DeleteEvent permanently removes an event. Used only for canceling
// pending (never-confirmed) events whose underlying condition disappeared
// before a second scan could confirm it - see internal/events.
func (s *Store) DeleteEvent(id int64) error {
	_, err := s.db.Exec(`DELETE FROM events WHERE id = ?`, id)
	return err
}

// ListActiveEvents returns every pending or confirmed event for an asset,
// newest first.
func (s *Store) ListActiveEvents(assetID int64) ([]Event, error) {
	return s.queryEvents(
		`SELECT id, asset_id, kind, port, proto, details, first_seen, last_seen, confirmed_at, scan_count, status
		 FROM events WHERE asset_id = ? AND status IN ('pending','confirmed') ORDER BY port, id`,
		assetID,
	)
}

// ListEvents returns up to `limit` events (any status) for an asset,
// newest first. limit <= 0 returns all.
func (s *Store) ListEvents(assetID int64, limit int) ([]Event, error) {
	query := `SELECT id, asset_id, kind, port, proto, details, first_seen, last_seen, confirmed_at, scan_count, status
	          FROM events WHERE asset_id = ? ORDER BY last_seen DESC, id DESC`
	if limit > 0 {
		return s.queryEvents(query+` LIMIT ?`, assetID, limit)
	}
	return s.queryEvents(query, assetID)
}

func (s *Store) queryEvents(query string, args ...any) ([]Event, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		e, err := scanEventRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanEventRow(row rowScanner) (Event, error) {
	var e Event
	var details sql.NullString
	var firstSeen, lastSeen string
	var confirmedAt sql.NullString

	err := row.Scan(&e.ID, &e.AssetID, &e.Kind, &e.Port, &e.Proto, &details, &firstSeen, &lastSeen, &confirmedAt, &e.ScanCount, &e.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	if err != nil {
		return Event{}, err
	}

	e.Details = nullableString(details)
	e.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	e.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	if confirmedAt.Valid {
		t, _ := time.Parse(time.RFC3339, confirmedAt.String)
		e.ConfirmedAt = &t
	}
	return e, nil
}
