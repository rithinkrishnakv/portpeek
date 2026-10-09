// Package diff is PortPeek's core comparison logic: given a set of current
// observations and a set of expected (baseline/accepted) ports, it decides
// what, if anything, looks like drift.
//
// This package is deliberately pure - it takes plain data in and returns
// plain data out, with no database or network access - so the comparison
// rules can be unit tested in isolation from storage and scanning.
package diff

import (
	"fmt"
	"strings"

	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// Candidate is one piece of detected drift between expected and observed
// state for a single (port, proto). It is "candidate" because it has not
// yet gone through two-scan confirmation - see internal/events.
type Candidate struct {
	Kind    string
	Port    int
	Proto   string
	Details string
}

// Compute compares the latest observations for an asset against its
// expected (baseline/accepted) state and returns every candidate drift
// condition found.
//
// Rules:
//   - An open port with no matching expected entry -> NEW_PORT.
//   - An expected port no longer observed open -> EXPECTED_SERVICE_MISSING.
//   - An expected port still open but reporting a different identified
//     service -> SERVICE_CHANGED.
//   - An expected port still open, with an expected service that used to
//     be identifiable, now reporting no identifiable service -> SERVICE_DISAPPEARED.
//
// Ports present in neither observations nor expected produce nothing.
// Ports present in `expected` but absent from `observations` entirely
// (i.e. not covered by this scan's port spec) also produce nothing - we
// never report drift for something we did not actually look at.
func Compute(observations []storage.Observation, expected []storage.Expected) []Candidate {
	expByPort := make(map[int]storage.Expected, len(expected))
	for _, e := range expected {
		expByPort[e.Port] = e
	}

	var out []Candidate

	for _, obs := range observations {
		exp, isExpected := expByPort[obs.Port]

		if !isExpected {
			if obs.State == "open" {
				svc := valueOr(obs.Service, "an unidentified service")
				out = append(out, Candidate{
					Kind:  storage.EventNewPort,
					Port:  obs.Port,
					Proto: obs.Proto,
					Details: fmt.Sprintf(
						"port is open and not present in the expected baseline (observed service: %s)", svc,
					),
				})
			}
			continue
		}

		// Port is expected.
		if obs.State != "open" {
			out = append(out, Candidate{
				Kind:  storage.EventExpectedServiceMissing,
				Port:  obs.Port,
				Proto: obs.Proto,
				Details: fmt.Sprintf(
					"expected open (service: %s) but observed state is %q", valueOr(exp.Service, "unspecified"), obs.State,
				),
			})
			continue
		}

		expSvc := valueOr(exp.Service, "")
		obsSvc := valueOr(obs.Service, "")
		expKnown := isKnownService(expSvc)
		obsKnown := isKnownService(obsSvc)

		switch {
		case expKnown && obsKnown && !strings.EqualFold(expSvc, obsSvc):
			out = append(out, Candidate{
				Kind:  storage.EventServiceChanged,
				Port:  obs.Port,
				Proto: obs.Proto,
				Details: fmt.Sprintf(
					"expected service %q, observed %q", expSvc, obsSvc,
				),
			})
		case expKnown && !obsKnown:
			out = append(out, Candidate{
				Kind:  storage.EventServiceDisappeared,
				Port:  obs.Port,
				Proto: obs.Proto,
				Details: fmt.Sprintf(
					"expected service %q is no longer identifiable on this port", expSvc,
				),
			})
		}
		// Otherwise - including the case where the baseline itself was
		// never identified (expected "Unknown TCP service" and still is)
		// - this is consistent with baseline: no candidate.
	}

	return out
}

func valueOr(s *string, def string) string {
	if s == nil || *s == "" {
		return def
	}
	return *s
}

// isKnownService reports whether svc represents an actual identification,
// as opposed to empty or PortPeek's own "could not identify this" marker.
func isKnownService(svc string) bool {
	return svc != "" && svc != "Unknown TCP service"
}
