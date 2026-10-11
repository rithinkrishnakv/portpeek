package diff

import (
	"strconv"
	"testing"

	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func strp(s string) *string { return &s }

func TestComputeNewPort(t *testing.T) {
	obs := []storage.Observation{
		{Port: 6379, Proto: "tcp", State: "open", Service: strp("Redis")},
	}
	var expected []storage.Expected

	got := Compute(obs, expected)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(got), got)
	}
	if got[0].Kind != storage.EventNewPort {
		t.Errorf("expected NEW_PORT, got %s", got[0].Kind)
	}
	if got[0].Port != 6379 {
		t.Errorf("expected port 6379, got %d", got[0].Port)
	}
}

func TestComputeNewPortOnlyWhenOpen(t *testing.T) {
	obs := []storage.Observation{
		{Port: 6379, Proto: "tcp", State: "closed"},
	}
	got := Compute(obs, nil)
	if len(got) != 0 {
		t.Fatalf("closed, non-expected port should not be a candidate: %+v", got)
	}
}

func TestComputeConsistentWithBaselineProducesNothing(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("expected no candidates, got %+v", got)
	}
}

func TestComputeExpectedServiceMissing(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "closed"},
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 1 || got[0].Kind != storage.EventExpectedServiceMissing {
		t.Fatalf("expected EXPECTED_SERVICE_MISSING, got %+v", got)
	}
}

func TestComputeServiceChanged(t *testing.T) {
	obs := []storage.Observation{
		{Port: 8080, Proto: "tcp", State: "open", Service: strp("HTTP")},
	}
	expected := []storage.Expected{
		{Port: 8080, Proto: "tcp", State: "open", Service: strp("Redis")},
	}
	got := Compute(obs, expected)
	if len(got) != 1 || got[0].Kind != storage.EventServiceChanged {
		t.Fatalf("expected SERVICE_CHANGED, got %+v", got)
	}
}

func TestComputeServiceChangedIsCaseInsensitive(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("ssh")},
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("expected no candidates for a case-only difference, got %+v", got)
	}
}

func TestComputeServiceDisappeared(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")},
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 1 || got[0].Kind != storage.EventServiceDisappeared {
		t.Fatalf("expected SERVICE_DISAPPEARED, got %+v", got)
	}
}

// --- Uncertain states (filtered/timeout) must never produce a candidate --
//
// filtered and timeout are PortPeek being honest that an attempt produced
// no reliable information - never evidence that a port or service closed.
// These are the pure-function-level regression tests for that rule; the
// internal/events package has the corresponding end-to-end lifecycle
// tests (a filtered/timeout reading must not confirm, cancel, or resolve
// any event either).

func TestComputeFilteredExpectedPortProducesNothing(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "filtered"},
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("a filtered reading on an expected port must produce no candidate, got %+v", got)
	}
}

func TestComputeTimeoutExpectedPortProducesNothing(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "timeout"},
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("a timeout reading on an expected port must produce no candidate, got %+v", got)
	}
}

func TestComputeFilteredUnexpectedPortProducesNothing(t *testing.T) {
	// Not expected, and not a definitive open or closed reading either -
	// must never be treated as a NEW_PORT (it isn't observed open) nor
	// as anything else.
	obs := []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "filtered"},
	}
	got := Compute(obs, nil)
	if len(got) != 0 {
		t.Fatalf("a filtered reading on an unexpected port must produce no candidate, got %+v", got)
	}
}

func TestComputeTimeoutUnexpectedPortProducesNothing(t *testing.T) {
	obs := []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "timeout"},
	}
	got := Compute(obs, nil)
	if len(got) != 0 {
		t.Fatalf("a timeout reading on an unexpected port must produce no candidate, got %+v", got)
	}
}

func TestComputeClosedUnexpectedPortProducesNothing(t *testing.T) {
	// A port that was never flagged as anything simply being closed is
	// not news - there is nothing to report missing.
	obs := []storage.Observation{
		{Port: 31337, Proto: "tcp", State: "closed"},
	}
	got := Compute(obs, nil)
	if len(got) != 0 {
		t.Fatalf("a closed reading on an unexpected, never-flagged port must produce no candidate, got %+v", got)
	}
}

// TestComputeBaselinedUnknownServiceStaysConsistent is a regression test:
// when a port was baselined while its service was unidentifiable (service
// == "Unknown TCP service"), observing that same "unidentified" state
// again must NOT be treated as SERVICE_DISAPPEARED - nothing has actually
// changed, the service was never identified in the first place.
func TestComputeBaselinedUnknownServiceStaysConsistent(t *testing.T) {
	obs := []storage.Observation{
		{Port: 34173, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")},
	}
	expected := []storage.Expected{
		{Port: 34173, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("expected no candidates when baseline and observation both unidentified, got %+v", got)
	}
}

// TestComputeUnknownServiceBecomingIdentifiedIsNotFlagged covers the
// opposite direction: a port baselined as unidentified that later becomes
// identifiable is an improvement, not drift.
func TestComputeUnknownServiceBecomingIdentifiedIsNotFlagged(t *testing.T) {
	obs := []storage.Observation{
		{Port: 34173, Proto: "tcp", State: "open", Service: strp("HTTP")},
	}
	expected := []storage.Expected{
		{Port: 34173, Proto: "tcp", State: "open", Service: strp("Unknown TCP service")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("expected no candidates when a previously-unknown service becomes identifiable, got %+v", got)
	}
}

func TestComputeUnscannedExpectedPortProducesNothing(t *testing.T) {
	// The port is baselined as expected, but this scan simply did not
	// check it (e.g. a narrower --ports). PortPeek must never claim
	// drift for something it did not actually look at.
	var obs []storage.Observation
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
	}
	got := Compute(obs, expected)
	if len(got) != 0 {
		t.Fatalf("expected no candidates for an unscanned expected port, got %+v", got)
	}
}

func TestComputeMultiplePortsIndependent(t *testing.T) {
	obs := []storage.Observation{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},  // matches baseline
		{Port: 80, Proto: "tcp", State: "open", Service: strp("HTTP")}, // new
		{Port: 6379, Proto: "tcp", State: "closed"},                    // expected but missing
	}
	expected := []storage.Expected{
		{Port: 22, Proto: "tcp", State: "open", Service: strp("SSH")},
		{Port: 6379, Proto: "tcp", State: "open", Service: strp("Redis")},
	}
	got := Compute(obs, expected)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %+v", len(got), got)
	}
	kinds := map[string]bool{}
	for _, c := range got {
		kinds[c.Kind+":"+strconv.Itoa(c.Port)] = true
	}
	if !kinds[storage.EventNewPort+":80"] {
		t.Errorf("expected NEW_PORT for port 80, got %+v", got)
	}
	if !kinds[storage.EventExpectedServiceMissing+":6379"] {
		t.Errorf("expected EXPECTED_SERVICE_MISSING for port 6379, got %+v", got)
	}
}
