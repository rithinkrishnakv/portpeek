package storage

import (
	"database/sql"
	"errors"
	"time"
)

// Scan is one invocation of `portpeek scan <asset>` that was persisted
// (scans run with --no-save never produce one of these).
type Scan struct {
	ID         int64
	AssetID    int64
	StartedAt  time.Time
	FinishedAt time.Time
	Vantage    string
	Scanner    string
	PortsSpec  string
}

// Observation is a single port's result within a scan.
type Observation struct {
	ID          int64
	ScanID      int64
	Port        int
	Proto       string
	State       string
	Service     *string
	VersionInfo *string
	Banner      *string
	Confidence  *string
	Evidence    *string
}

// CreateScan inserts a new scan row and returns it with its assigned ID.
func (s *Store) CreateScan(assetID int64, startedAt, finishedAt time.Time, vantage, scanner, portsSpec string) (Scan, error) {
	res, err := s.db.Exec(
		`INSERT INTO scans(asset_id, started_at, finished_at, vantage, scanner, ports_spec)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		assetID, startedAt.UTC().Format(time.RFC3339), finishedAt.UTC().Format(time.RFC3339), vantage, scanner, portsSpec,
	)
	if err != nil {
		return Scan{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Scan{}, err
	}
	return s.GetScan(id)
}

// GetScan looks up a scan by ID.
func (s *Store) GetScan(id int64) (Scan, error) {
	row := s.db.QueryRow(
		`SELECT id, asset_id, started_at, finished_at, vantage, scanner, ports_spec
		 FROM scans WHERE id = ?`, id,
	)
	return scanScanRow(row)
}

// LatestScan returns the most recent persisted scan for an asset.
func (s *Store) LatestScan(assetID int64) (Scan, error) {
	row := s.db.QueryRow(
		`SELECT id, asset_id, started_at, finished_at, vantage, scanner, ports_spec
		 FROM scans WHERE asset_id = ? ORDER BY started_at DESC, id DESC LIMIT 1`, assetID,
	)
	return scanScanRow(row)
}

// ListScans returns up to `limit` scans for an asset, newest first. A
// limit <= 0 returns all scans.
func (s *Store) ListScans(assetID int64, limit int) ([]Scan, error) {
	query := `SELECT id, asset_id, started_at, finished_at, vantage, scanner, ports_spec
	          FROM scans WHERE asset_id = ? ORDER BY started_at DESC, id DESC`
	args := []any{assetID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		sc, err := scanScanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func scanScanRow(row rowScanner) (Scan, error) {
	var sc Scan
	var started, finished string
	err := row.Scan(&sc.ID, &sc.AssetID, &started, &finished, &sc.Vantage, &sc.Scanner, &sc.PortsSpec)
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	if err != nil {
		return Scan{}, err
	}
	sc.StartedAt, _ = time.Parse(time.RFC3339, started)
	sc.FinishedAt, _ = time.Parse(time.RFC3339, finished)
	return sc, nil
}

// AddObservations bulk-inserts observations for a scan inside a single
// transaction.
func (s *Store) AddObservations(scanID int64, obs []Observation) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(
		`INSERT INTO observations(scan_id, port, proto, state, service, version_info, banner, confidence, evidence)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, o := range obs {
		if _, err := stmt.Exec(scanID, o.Port, o.Proto, o.State, o.Service, o.VersionInfo, o.Banner, o.Confidence, o.Evidence); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetObservations returns every observation recorded for a scan, ordered
// by port.
func (s *Store) GetObservations(scanID int64) ([]Observation, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, port, proto, state, service, version_info, banner, confidence, evidence
		 FROM observations WHERE scan_id = ? ORDER BY port`, scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Observation
	for rows.Next() {
		var o Observation
		var service, versionInfo, banner, confidence, evidence sql.NullString
		if err := rows.Scan(&o.ID, &o.ScanID, &o.Port, &o.Proto, &o.State, &service, &versionInfo, &banner, &confidence, &evidence); err != nil {
			return nil, err
		}
		o.Service = nullableString(service)
		o.VersionInfo = nullableString(versionInfo)
		o.Banner = nullableString(banner)
		o.Confidence = nullableString(confidence)
		o.Evidence = nullableString(evidence)
		out = append(out, o)
	}
	return out, rows.Err()
}

// ObservationsForPort returns the history of observations for a single
// port on an asset, newest first, across all retained scans.
func (s *Store) ObservationsForPort(assetID int64, port int, limit int) ([]Observation, []Scan, error) {
	query := `SELECT o.id, o.scan_id, o.port, o.proto, o.state, o.service, o.version_info, o.banner, o.confidence, o.evidence,
	                 s.id, s.asset_id, s.started_at, s.finished_at, s.vantage, s.scanner, s.ports_spec
	          FROM observations o
	          JOIN scans s ON s.id = o.scan_id
	          WHERE s.asset_id = ? AND o.port = ?
	          ORDER BY s.started_at DESC, s.id DESC`
	args := []any{assetID, port}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var obs []Observation
	var scans []Scan
	for rows.Next() {
		var o Observation
		var sc Scan
		var service, versionInfo, banner, confidence, evidence sql.NullString
		var started, finished string
		if err := rows.Scan(
			&o.ID, &o.ScanID, &o.Port, &o.Proto, &o.State, &service, &versionInfo, &banner, &confidence, &evidence,
			&sc.ID, &sc.AssetID, &started, &finished, &sc.Vantage, &sc.Scanner, &sc.PortsSpec,
		); err != nil {
			return nil, nil, err
		}
		o.Service = nullableString(service)
		o.VersionInfo = nullableString(versionInfo)
		o.Banner = nullableString(banner)
		o.Confidence = nullableString(confidence)
		o.Evidence = nullableString(evidence)
		sc.StartedAt, _ = time.Parse(time.RFC3339, started)
		sc.FinishedAt, _ = time.Parse(time.RFC3339, finished)
		obs = append(obs, o)
		scans = append(scans, sc)
	}
	return obs, scans, rows.Err()
}

// DeleteScansOlderThan removes scans (and, via cascade, their
// observations) started before cutoff, for the given asset, always
// preserving the single most recent scan regardless of age.
func (s *Store) DeleteScansOlderThan(assetID int64, cutoff time.Time) (int64, error) {
	latest, err := s.LatestScan(assetID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return 0, err
	}

	var res sql.Result
	if errors.Is(err, ErrNotFound) {
		res, err = s.db.Exec(
			`DELETE FROM scans WHERE asset_id = ? AND started_at < ?`,
			assetID, cutoff.UTC().Format(time.RFC3339),
		)
	} else {
		res, err = s.db.Exec(
			`DELETE FROM scans WHERE asset_id = ? AND started_at < ? AND id != ?`,
			assetID, cutoff.UTC().Format(time.RFC3339), latest.ID,
		)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
