package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned when a lookup (asset, scan, etc.) finds nothing.
var ErrNotFound = errors.New("not found")

// ErrAlreadyExists is returned when creating an asset whose label is
// already in use.
var ErrAlreadyExists = errors.New("already exists")

// Asset is a user-named scan target. The identity-evidence fields are
// reserved for future use (see internal/storage schema docs / README
// roadmap) and are never populated from assumptions - only from fields
// PortPeek actually observed.
type Asset struct {
	ID                    int64
	Label                 string
	Host                  string
	CreatedAt             time.Time
	MACAddress            *string
	CertFingerprint       *string
	SSHHostKeyFingerprint *string
	MDNSIdentity          *string
	// AllowPublicTarget is an explicit, persistent opt-out of the
	// public-target scan confirmation (see internal/safety and
	// cmd_scan.go's --confirm-public-target): once true, `scan` no
	// longer asks for per-invocation confirmation when this asset's host
	// resolves to a public address. Set via `add --allow-public-target`
	// or SetAllowPublicTarget; false by default for every asset.
	AllowPublicTarget bool
}

// CreateAsset registers a new asset. Returns ErrAlreadyExists if the label
// is already taken.
func (s *Store) CreateAsset(label, host string) (Asset, error) {
	res, err := s.db.Exec(
		`INSERT INTO assets(label, host, created_at) VALUES(?, ?, ?)`,
		label, host, now(),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return Asset{}, fmt.Errorf("asset %q: %w", label, ErrAlreadyExists)
		}
		return Asset{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Asset{}, err
	}
	return s.GetAssetByID(id)
}

// GetAsset looks up an asset by its label.
func (s *Store) GetAsset(label string) (Asset, error) {
	row := s.db.QueryRow(
		`SELECT id, label, host, created_at, mac_address, cert_fingerprint,
		        ssh_host_key_fingerprint, mdns_identity, allow_public_target
		 FROM assets WHERE label = ?`, label,
	)
	return scanAsset(row)
}

// GetAssetByID looks up an asset by its numeric ID.
func (s *Store) GetAssetByID(id int64) (Asset, error) {
	row := s.db.QueryRow(
		`SELECT id, label, host, created_at, mac_address, cert_fingerprint,
		        ssh_host_key_fingerprint, mdns_identity, allow_public_target
		 FROM assets WHERE id = ?`, id,
	)
	return scanAsset(row)
}

// SetAllowPublicTarget persists this asset's explicit, standing opt-out of
// the public-target scan confirmation (see internal/safety). It is kept
// separate from CreateAsset rather than added as a new parameter so
// CreateAsset's existing signature - and every one of its many existing
// callers, test and production alike - is left untouched.
func (s *Store) SetAllowPublicTarget(assetID int64, allow bool) error {
	res, err := s.db.Exec(`UPDATE assets SET allow_public_target = ? WHERE id = ?`, allow, assetID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAssets returns all assets, ordered by label.
func (s *Store) ListAssets() ([]Asset, error) {
	rows, err := s.db.Query(
		`SELECT id, label, host, created_at, mac_address, cert_fingerprint,
		        ssh_host_key_fingerprint, mdns_identity, allow_public_target
		 FROM assets ORDER BY label`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RemoveAsset deletes an asset and (via ON DELETE CASCADE) every scan,
// observation, expected-state row, and event associated with it.
func (s *Store) RemoveAsset(label string) error {
	res, err := s.db.Exec(`DELETE FROM assets WHERE label = ?`, label)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("asset %q: %w", label, ErrNotFound)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAsset(row rowScanner) (Asset, error) {
	var a Asset
	var createdAt string
	var mac, certFP, sshFP, mdns sql.NullString
	var allowPublic bool

	err := row.Scan(&a.ID, &a.Label, &a.Host, &createdAt, &mac, &certFP, &sshFP, &mdns, &allowPublic)
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}

	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	a.MACAddress = nullableString(mac)
	a.CertFingerprint = nullableString(certFP)
	a.SSHHostKeyFingerprint = nullableString(sshFP)
	a.MDNSIdentity = nullableString(mdns)
	a.AllowPublicTarget = allowPublic
	return a, nil
}

func nullableString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}

func isUniqueConstraintErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
