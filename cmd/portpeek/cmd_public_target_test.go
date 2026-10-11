package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rithinkrishnakv/portpeek/internal/output"
)

// captureStderr redirects os.Stderr for the duration of fn, returning
// everything written to it along with fn's own return value. Mirrors
// captureStdout in cli_test.go, for tests that need to inspect the
// public-target refusal message, which (like all of PortPeek's error
// output) goes to stderr.
func captureStderr(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	code := fn()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return buf.String(), code
}

const refusalSnippet = "refusing to scan a public target"

// TestCLI_ScanRefusesPublicTargetByDefault is the core regression test for
// requirement #3 of the release review: by default, scanning an asset
// whose host resolves to a public (non-private) address must be refused,
// not silently performed - and nothing should be persisted when it is
// refused.
func TestCLI_ScanRefusesPublicTargetByDefault(t *testing.T) {
	newTestDB(t)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "pub", "8.8.8.8"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	stderr, code := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub", "--ports", "80", "--timeout", "50"})
		})
		return c
	})
	if code != ExitError {
		t.Fatalf("scan of a public target without confirmation: expected exit %d, got %d (stderr=%s)", ExitError, code, stderr)
	}
	if !strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("expected refusal message on stderr, got %q", stderr)
	}

	// Duplicate-prevention / no partial persistence: a refused scan must
	// not have written a scan row, so history shows nothing.
	out, code := captureStdout(t, func() int { return run([]string{"history", "pub", "--json"}) })
	if code != ExitClean {
		t.Fatalf("history: expected exit 0, got %d (output=%s)", code, out)
	}
	var scans []map[string]any
	if err := json.Unmarshal([]byte(out), &scans); err != nil {
		t.Fatalf("decode history JSON: %v (output=%s)", err, out)
	}
	if len(scans) != 0 {
		t.Fatalf("expected no persisted scans after a refused public-target scan, got %d", len(scans))
	}

	// Refusing twice in a row must behave identically - no state is
	// mutated by the refusal itself that would change the outcome on a
	// second attempt.
	stderr2, code2 := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub", "--ports", "80", "--timeout", "50"})
		})
		return c
	})
	if code2 != ExitError || !strings.Contains(stderr2, refusalSnippet) {
		t.Fatalf("expected the same refusal on a second attempt, got code=%d stderr=%q", code2, stderr2)
	}
}

// TestCLI_ScanConfirmPublicTargetBypassesGateForOneInvocation covers the
// per-invocation --confirm-public-target bypass: the asset itself has no
// standing allowance, but passing the flag lets this one scan proceed past
// the safety gate (the refusal message must not appear).
func TestCLI_ScanConfirmPublicTargetBypassesGateForOneInvocation(t *testing.T) {
	newTestDB(t)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "pub", "8.8.8.8"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	stderr, _ := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub", "--ports", "80", "--timeout", "50", "--no-save", "--confirm-public-target"})
		})
		return c
	})
	if strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("expected --confirm-public-target to bypass the safety gate, but got refusal: %q", stderr)
	}

	// The bypass must be strictly per-invocation: scanning again without
	// the flag must be refused again.
	stderr2, code2 := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub", "--ports", "80", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if code2 != ExitError || !strings.Contains(stderr2, refusalSnippet) {
		t.Fatalf("expected the per-invocation bypass to not persist across invocations, got code=%d stderr=%q", code2, stderr2)
	}
}

// TestCLI_AllowPublicTargetCommandGrantsStandingBypass covers the
// persistent allowlist path end-to-end: `add --allow-public-target` at
// creation time, and `allow-public-target` / `allow-public-target --off`
// toggling it for an asset that already exists.
func TestCLI_AllowPublicTargetCommandGrantsStandingBypass(t *testing.T) {
	newTestDB(t)

	// Created with the flag already set.
	if _, code := captureStdout(t, func() int { return run([]string{"add", "pub1", "8.8.8.8", "--allow-public-target"}) }); code != ExitClean {
		t.Fatalf("add --allow-public-target: expected exit 0, got %d", code)
	}
	stderr, _ := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub1", "--ports", "80", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("expected an asset created with --allow-public-target to bypass the gate, got refusal: %q", stderr)
	}

	// Created without the flag, then granted via the standalone command.
	if _, code := captureStdout(t, func() int { return run([]string{"add", "pub2", "8.8.4.4"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}
	stderrBefore, codeBefore := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub2", "--ports", "80", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if codeBefore != ExitError || !strings.Contains(stderrBefore, refusalSnippet) {
		t.Fatalf("expected pub2 to be refused before allow-public-target is run, got code=%d stderr=%q", codeBefore, stderrBefore)
	}

	if _, code := captureStdout(t, func() int { return run([]string{"allow-public-target", "pub2"}) }); code != ExitClean {
		t.Fatalf("allow-public-target: expected exit 0, got %d", code)
	}

	out, code := captureStdout(t, func() int { return run([]string{"list", "--json"}) })
	if code != ExitClean {
		t.Fatalf("list --json: expected exit 0, got %d", code)
	}
	var assets []output.AssetJSON
	if err := json.Unmarshal([]byte(out), &assets); err != nil {
		t.Fatalf("decode list JSON: %v", err)
	}
	var found bool
	for _, a := range assets {
		if a.Label == "pub2" {
			found = true
			if !a.AllowPublicTarget {
				t.Fatalf("expected pub2.AllowPublicTarget to be true after allow-public-target, got false")
			}
		}
	}
	if !found {
		t.Fatalf("expected pub2 in asset list")
	}

	stderrAfter, _ := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub2", "--ports", "80", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if strings.Contains(stderrAfter, refusalSnippet) {
		t.Fatalf("expected pub2 to bypass the gate after allow-public-target, got refusal: %q", stderrAfter)
	}

	// --off reverts it.
	if _, code := captureStdout(t, func() int { return run([]string{"allow-public-target", "pub2", "--off"}) }); code != ExitClean {
		t.Fatalf("allow-public-target --off: expected exit 0, got %d", code)
	}
	stderrReverted, codeReverted := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub2", "--ports", "80", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if codeReverted != ExitError || !strings.Contains(stderrReverted, refusalSnippet) {
		t.Fatalf("expected pub2 to be refused again after allow-public-target --off, got code=%d stderr=%q", codeReverted, stderrReverted)
	}
}

// TestCLI_ScanNeverBlocksPrivateTarget ensures the safety gate never
// interferes with ordinary private/loopback targets, which is the
// overwhelmingly common case and must remain completely frictionless.
func TestCLI_ScanNeverBlocksPrivateTarget(t *testing.T) {
	newTestDB(t)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "priv", "10.0.0.5"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	stderr, code := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "priv", "--ports", "1", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("expected a private target to never be refused by the safety gate, got: %q", stderr)
	}
	if code == ExitError && strings.Contains(stderr, "resolve target") {
		t.Fatalf("unexpected resolution error for a private IP literal: %q", stderr)
	}
}
