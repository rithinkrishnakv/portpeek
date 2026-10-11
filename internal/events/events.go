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

// portProto identifies a tracked port regardless of event kind.
type portProto struct {
	Port  int
	Proto string
}

// Reconcile compares the given observations against the asset's expected
// state, updates the event table accordingly, and returns a summary of
// what happened. It is called once per saved scan.
//
// Every event kind - NEW_PORT, PORT_CLOSED, SERVICE_CHANGED,
// SERVICE_DISAPPEARED, EXPECTED_SERVICE_MISSING alike - goes through
// exactly the same two-scan pending -> confirmed rule, with no shortcuts:
// a condition must be observed on two consecutive *definitive* scans
// before it is confirmed drift.
//
// The formal rule for "consecutive" - this is the part that governs how
// "filtered" and "timeout" readings interact with a pending or confirmed
// event, spelled out explicitly since it's easy to get subtly wrong:
//
//   - A reading of "open" or "closed" is definitive: it is real evidence,
//     and only a definitive reading ever creates, advances (scan_count
//     and status), resolves, or cancels an event. See internal/diff's
//     Compute and the PORT_CLOSED derivation below for the one definitive
//     case each kind reacts to.
//   - A reading of "filtered" or "timeout" is never evidence of anything
//   - not of the original condition continuing, and not of it having
//     gone away. For this purpose it is handled identically to the port
//     simply not having been scanned this round at all: no event is
//     created, touched, confirmed, resolved, or cancelled because of it.
//   - Consequently, an uncertain reading *pauses* an in-progress
//     confirmation streak rather than resetting or advancing it: a
//     pending event stays pending at the same scan_count, and a confirmed
//     event stays confirmed at the same scan_count, until the next
//     definitive reading for that port arrives - however many scans in a
//     row are uncertain in between. "Two consecutive scans" therefore
//     means two consecutive *definitive* scans of the same condition, not
//     two consecutive calls to Reconcile.
//
// This is what keeps a transient scan failure from ever producing a false
// confirmed-drift result, and - just as important - from ever silently
// erasing a real one. See internal/events/events_test.go's
// "Release-review regression suite" for the explicit pending/confirmed x
// timeout/filtered coverage of this contract, including its application
// to PORT_CLOSED's own, separately-tracked confirmation cycle.
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

	// PORT_CLOSED cannot be computed by the pure internal/diff package
	// from observations and expected state alone: "closed" is only
	// interesting in contrast to a port's own event history (specifically,
	// whether it was ever flagged NEW_PORT - an unexpected, previously-open
	// exposure PortPeek is actively tracking), not against a user-declared
	// baseline. It is re-derived fresh here, every scan, as a candidate
	// with exactly the same property every other candidate has: it fires
	// every scan the underlying condition still holds (the port stays
	// definitively closed) and is simply absent the moment it doesn't -
	// which is what lets it flow through the exact same generic
	// pending -> confirmed -> resolved machinery below as every other
	// kind, with no special-casing, and the exact same two-scan rule.
	//
	// It is derived once per tracked (port, proto) - not once per active
	// event referencing that port - so a port that currently has both an
	// active NEW_PORT event (not yet resolved) and an active PORT_CLOSED
	// event (still pending its own confirmation) never produces two
	// competing candidates in the same call.
	//
	// A NEW_PORT event only starts tracking for PORT_CLOSED purposes once
	// it is itself CONFIRMED - a still-pending, never-confirmed NEW_PORT
	// is just a one-off blip, not a tracked exposure; if it disappears
	// before its own confirmation, step 3 below cancels it outright, the
	// same as any other never-confirmed finding, with no PORT_CLOSED
	// event ever created for it. A PORT_CLOSED event, once it exists, is
	// tracked regardless of its own pending/confirmed status, so it keeps
	// being re-evaluated (touched, confirmed, or cancelled) every scan
	// until it is resolved one way or the other.
	tracked := make(map[portProto]bool)
	for _, ev := range active {
		if (ev.Kind == storage.EventNewPort && ev.Status == storage.StatusConfirmed) || ev.Kind == storage.EventPortClosed {
			tracked[portProto{ev.Port, ev.Proto}] = true
		}
	}
	for pp := range tracked {
		obs, scanned := obsByPort[pp.Port]
		if !scanned || obs.Proto != pp.Proto || obs.State != storage.StateClosed {
			continue
		}
		candidates = append(candidates, diff.Candidate{
			Kind:  storage.EventPortClosed,
			Port:  pp.Port,
			Proto: pp.Proto,
			Details: fmt.Sprintf(
				"port %d/%s, previously an active (confirmed or pending-confirmation) exposure, is now definitively closed (connection refused)",
				pp.Port, pp.Proto,
			),
		})
	}

	// 1. Advance or create an event for every current candidate -
	// including the derived PORT_CLOSED ones computed above.
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

	// 2. Once a derived PORT_CLOSED event reaches confirmed status (its
	// own two-scan rule satisfied, same as above), the NEW_PORT exposure
	// it closes out is done: resolve it. This is checked by re-reading
	// current state rather than relying on anything computed above, so it
	// is correct whether PORT_CLOSED was *just* confirmed this call or
	// was already confirmed by an earlier scan (e.g. if a prior run
	// failed to resolve it for some reason) - it is naturally a no-op
	// once NEW_PORT is already resolved, since ListActiveEvents/
	// FindActiveEvent simply won't find it any more.
	for pp := range tracked {
		pcEvent, err := st.FindActiveEvent(assetID, storage.EventPortClosed, pp.Port, pp.Proto)
		if err != nil || pcEvent.Status != storage.StatusConfirmed {
			continue
		}
		npEvent, err := st.FindActiveEvent(assetID, storage.EventNewPort, pp.Port, pp.Proto)
		if err != nil {
			continue
		}
		resolved, err := st.SetEventStatus(npEvent.ID, storage.StatusResolved)
		if err != nil {
			return summary, fmt.Errorf("resolve event %d: %w", npEvent.ID, err)
		}
		summary.Resolved = append(summary.Resolved, resolved)
		delete(activeByKey, key(npEvent.Kind, npEvent.Port, npEvent.Proto))
	}

	// 3. Everything left in activeByKey had no matching candidate this
	// scan. Only act on it if this scan produced a *definitive* result
	// for that port:
	//   - "open": whatever drift this event represents is gone - resolve
	//     it if confirmed, cancel it outright if it never got that far.
	//   - "closed": a different candidate superseded it this round (e.g.
	//     an expected port's SERVICE_CHANGED event, now that the port is
	//     EXPECTED_SERVICE_MISSING instead) - same resolve/cancel rule.
	//   - "filtered"/"timeout", or genuinely unscanned this round: no
	//     reliable new information was gained about this port at all, so
	//     nothing is touched, confirmed, resolved, or cancelled. This is
	//     what prevents a transient scan failure from ever clearing - or
	//     ever confirming - a finding by itself.
	// A confirmed NEW_PORT event showing closed is deliberately excluded
	// here even though "closed" is otherwise definitive: its resolution
	// is owned exclusively by step 2 above, gated on PORT_CLOSED's own
	// two-scan confirmation, not on a single closed reading.
	for _, ev := range activeByKey {
		obs, scanned := obsByPort[ev.Port]
		if !scanned {
			continue
		}
		if obs.State != storage.StateOpen && obs.State != storage.StateClosed {
			continue
		}
		if ev.Kind == storage.EventNewPort && ev.Status == storage.StatusConfirmed {
			continue
		}

		if ev.Status == storage.StatusPending {
			if err := st.DeleteEvent(ev.ID); err != nil {
				return summary, fmt.Errorf("cancel event %d: %w", ev.ID, err)
			}
			summary.Cancelled = append(summary.Cancelled, ev)
			continue
		}

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
