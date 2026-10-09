// Package events owns PortPeek's event lifecycle: turning diff
// candidates into tracked events, requiring two consecutive scans before
// a candidate becomes "confirmed", and resolving or cancelling events
// whose underlying condition goes away.
package events

import (
	"fmt"

	"github.com/rithinkrishnakv/portpeek/internal/diff"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// Summary reports what changed during one Reconcile call, so callers (the
// `scan` and `diff` commands) can print a useful, human-scale summary
// instead of a raw event dump.
type Summary struct {
	NewlyPending   []storage.Event
	NewlyConfirmed []storage.Event
	StillPending   []storage.Event
	StillConfirmed []storage.Event
	Resolved       []storage.Event
	Cancelled      []storage.Event
}

func key(kind string, port int, proto string) string {
	return fmt.Sprintf("%s|%d|%s", kind, port, proto)
}

// Reconcile compares the given observations against the asset's expected
// state, updates the event table accordingly, and returns a summary of
// what happened. It is called once per saved scan.
func Reconcile(st *storage.Store, assetID int64, observations []storage.Observation) (Summary, error) {
	var summary Summary

	expected, err := st.ListExpected(assetID)
	if err != nil {
		return summary, fmt.Errorf("load expected state: %w", err)
	}

	candidates := diff.Compute(observations, expected)

	obsByPort := make(map[int]storage.Observation, len(observations))
	for _, o := range observations {
		obsByPort[o.Port] = o
	}

	active, err := st.ListActiveEvents(assetID)
	if err != nil {
		return summary, fmt.Errorf("load active events: %w", err)
	}
	activeByKey := make(map[string]storage.Event, len(active))
	for _, e := range active {
		activeByKey[key(e.Kind, e.Port, e.Proto)] = e
	}

	// 1. Advance or create an event for every current candidate.
	for _, c := range candidates {
		ck := key(c.Kind, c.Port, c.Proto)
		if existing, ok := activeByKey[ck]; ok {
			updated, err := st.TouchEvent(existing.ID, strPtr(c.Details))
			if err != nil {
				return summary, fmt.Errorf("update event %d: %w", existing.ID, err)
			}
			if updated.Status == storage.StatusPending && updated.ScanCount >= 2 {
				updated, err = st.SetEventStatus(updated.ID, storage.StatusConfirmed)
				if err != nil {
					return summary, fmt.Errorf("confirm event %d: %w", existing.ID, err)
				}
				summary.NewlyConfirmed = append(summary.NewlyConfirmed, updated)
			} else if updated.Status == storage.StatusPending {
				summary.StillPending = append(summary.StillPending, updated)
			} else {
				summary.StillConfirmed = append(summary.StillConfirmed, updated)
			}
			delete(activeByKey, ck)
			continue
		}

		created, err := st.CreateEvent(assetID, c.Kind, c.Port, c.Proto, strPtr(c.Details))
		if err != nil {
			return summary, fmt.Errorf("create event: %w", err)
		}
		summary.NewlyPending = append(summary.NewlyPending, created)
	}

	// 2. Everything left in activeByKey had no matching candidate this
	// scan. Only act on it if this scan actually covered that port -
	// otherwise we simply don't know anything new and leave it alone.
	for _, ev := range activeByKey {
		if _, scanned := obsByPort[ev.Port]; !scanned {
			continue
		}

		if ev.Kind == storage.EventNewPort && ev.Status == storage.StatusConfirmed {
			details := fmt.Sprintf("previously confirmed open port %d/%s is no longer open", ev.Port, ev.Proto)
			pc, err := st.CreateEvent(assetID, storage.EventPortClosed, ev.Port, ev.Proto, &details)
			if err != nil {
				return summary, fmt.Errorf("create PORT_CLOSED event: %w", err)
			}
			pc, err = st.SetEventStatus(pc.ID, storage.StatusConfirmed)
			if err != nil {
				return summary, fmt.Errorf("confirm PORT_CLOSED event: %w", err)
			}
			summary.NewlyConfirmed = append(summary.NewlyConfirmed, pc)

			resolved, err := st.SetEventStatus(ev.ID, storage.StatusResolved)
			if err != nil {
				return summary, fmt.Errorf("resolve event %d: %w", ev.ID, err)
			}
			summary.Resolved = append(summary.Resolved, resolved)
			continue
		}

		if ev.Status == storage.StatusPending {
			if err := st.DeleteEvent(ev.ID); err != nil {
				return summary, fmt.Errorf("cancel event %d: %w", ev.ID, err)
			}
			summary.Cancelled = append(summary.Cancelled, ev)
			continue
		}

		// Confirmed event whose condition is gone: resolved.
		resolved, err := st.SetEventStatus(ev.ID, storage.StatusResolved)
		if err != nil {
			return summary, fmt.Errorf("resolve event %d: %w", ev.ID, err)
		}
		summary.Resolved = append(summary.Resolved, resolved)
	}

	return summary, nil
}

// HasConfirmedDrift reports whether any confirmed (not yet accepted)
// events exist among active.
func HasConfirmedDrift(active []storage.Event) bool {
	for _, e := range active {
		if e.Status == storage.StatusConfirmed {
			return true
		}
	}
	return false
}

// HasPendingDrift reports whether any pending (unconfirmed) events exist
// among active.
func HasPendingDrift(active []storage.Event) bool {
	for _, e := range active {
		if e.Status == storage.StatusPending {
			return true
		}
	}
	return false
}

func strPtr(s string) *string { return &s }
