package storage

import "time"

// CleanupReport summarizes what a cleanup pass removed.
type CleanupReport struct {
	ScansDeleted  int64
	EventsDeleted int64
}

// Cleanup removes scan history (and their observations, via cascade)
// older than retentionDays for every asset, always preserving each
// asset's single most recent scan. It also removes resolved/accepted
// events older than retentionDays; pending and confirmed events are never
// removed by cleanup, since they represent drift the user has not yet
// acted on.
func (s *Store) Cleanup(retentionDays int) (CleanupReport, error) {
	var report CleanupReport
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	assets, err := s.ListAssets()
	if err != nil {
		return report, err
	}

	for _, a := range assets {
		n, err := s.DeleteScansOlderThan(a.ID, cutoff)
		if err != nil {
			return report, err
		}
		report.ScansDeleted += n
	}

	res, err := s.db.Exec(
		`DELETE FROM events WHERE status IN ('resolved','accepted') AND last_seen < ?`,
		cutoff.Format(time.RFC3339),
	)
	if err != nil {
		return report, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return report, err
	}
	report.EventsDeleted = n

	return report, nil
}
