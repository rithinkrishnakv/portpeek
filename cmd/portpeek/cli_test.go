package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rithinkrishnakv/portpeek/internal/output"
)

// captureStdout redirects os.Stdout for the duration of fn, returning
// everything written to it along with fn's own return value (the CLI's
// exit code). Tests in this file never run in parallel with each other,
// so swapping the package-level os.Stdout is safe.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	code := fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return buf.String(), code
}

// newTestDB points PORTPEEK_DB at a fresh, isolated temp file for the
// duration of the test.
func newTestDB(t *testing.T) {
	t.Helper()
	t.Setenv("PORTPEEK_DB", filepath.Join(t.TempDir(), "portpeek.db"))
}

// listenOpenPort starts a listener that accepts (and immediately drops)
// connections, simulating an open TCP port that speaks no known
// protocol - every fingerprint probe against it will time out, so
// PortPeek identifies it as "Unknown TCP service". This is deliberately
// the scenario that originally exposed the diff engine's
// baselined-unknown-service false positive bug.
func listenOpenPort(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestCLI_AddListRemove(t *testing.T) {
	newTestDB(t)

	out, code := captureStdout(t, func() int { return run([]string{"add", "srv1", "10.0.0.5"}) })
	if code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d (output=%s)", code, out)
	}

	out, code = captureStdout(t, func() int { return run([]string{"list"}) })
	if code != ExitClean {
		t.Fatalf("list: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(out), []byte("srv1")) {
		t.Fatalf("expected list output to mention srv1, got %q", out)
	}

	// Duplicate add must fail cleanly.
	_, code = captureStdout(t, func() int { return run([]string{"add", "srv1", "10.0.0.9"}) })
	if code != ExitError {
		t.Fatalf("duplicate add: expected exit %d, got %d", ExitError, code)
	}

	out, code = captureStdout(t, func() int { return run([]string{"list", "--json"}) })
	if code != ExitClean {
		t.Fatalf("list --json: expected exit 0, got %d", code)
	}
	var assets []output.AssetJSON
	if err := json.Unmarshal([]byte(out), &assets); err != nil {
		t.Fatalf("unmarshal list --json: %v (output=%s)", err, out)
	}
	if len(assets) != 1 || assets[0].Label != "srv1" {
		t.Fatalf("unexpected assets: %+v", assets)
	}

	_, code = captureStdout(t, func() int { return run([]string{"remove", "srv1"}) })
	if code != ExitClean {
		t.Fatalf("remove: expected exit 0, got %d", code)
	}

	_, code = captureStdout(t, func() int { return run([]string{"remove", "srv1"}) })
	if code != ExitError {
		t.Fatalf("remove non-existent: expected exit %d, got %d", ExitError, code)
	}
}

func TestCLI_UnknownCommandAndVersion(t *testing.T) {
	newTestDB(t)

	_, code := captureStdout(t, func() int { return run([]string{"not-a-real-command"}) })
	if code != ExitError {
		t.Fatalf("unknown command: expected exit %d, got %d", ExitError, code)
	}

	out, code := captureStdout(t, func() int { return run([]string{"version"}) })
	if code != ExitClean {
		t.Fatalf("version: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(out), []byte("portpeek")) {
		t.Fatalf("expected version output to mention portpeek, got %q", out)
	}

	out, code = captureStdout(t, func() int { return run(nil) })
	if code != ExitError {
		t.Fatalf("no args: expected exit %d, got %d", ExitError, code)
	}
	if !bytes.Contains([]byte(out), []byte("USAGE")) {
		t.Fatalf("expected usage text, got %q", out)
	}
}

// TestCLI_FullWorkflowExitCodes exercises the entire scan -> baseline ->
// scan lifecycle end to end and asserts PortPeek's documented exit codes
// at every stage, including the regression scenario that originally
// uncovered the "Unknown TCP service" false-positive drift bug: baselining
// a port whose service could not be identified must not cause every
// subsequent identical scan to report drift.
func TestCLI_FullWorkflowExitCodes(t *testing.T) {
	newTestDB(t)
	host, port := listenOpenPort(t)
	portsFlag := itoa(port)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "target", host}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	scanArgs := []string{"scan", "target", "--ports", portsFlag, "--timeout", "50"}

	// 1st scan: a brand-new open port with no baseline yet -> NEW_PORT is
	// only pending after one scan, so this must be ExitPendingDrift.
	out, code := captureStdout(t, func() int { return run(scanArgs) })
	if code != ExitPendingDrift {
		t.Fatalf("1st scan: expected exit %d (pending drift), got %d\noutput:\n%s", ExitPendingDrift, code, out)
	}

	// 2nd identical scan: NEW_PORT confirms -> ExitConfirmedDrift.
	out, code = captureStdout(t, func() int { return run(scanArgs) })
	if code != ExitConfirmedDrift {
		t.Fatalf("2nd scan: expected exit %d (confirmed drift), got %d\noutput:\n%s", ExitConfirmedDrift, code, out)
	}

	// Baseline: accept current state as expected.
	out, code = captureStdout(t, func() int { return run([]string{"baseline", "target"}) })
	if code != ExitClean {
		t.Fatalf("baseline: expected exit 0, got %d\noutput:\n%s", code, out)
	}

	// 3rd scan, now baselined and still identical: must be clean. This is
	// the exact scenario that used to spuriously report SERVICE_DISAPPEARED
	// for a baselined "Unknown TCP service" port.
	out, code = captureStdout(t, func() int { return run(scanArgs) })
	if code != ExitClean {
		t.Fatalf("3rd scan (post-baseline): expected exit 0 (clean), got %d\noutput:\n%s", code, out)
	}

	// 4th scan: still clean, proving it wasn't a one-off.
	out, code = captureStdout(t, func() int { return run(scanArgs) })
	if code != ExitClean {
		t.Fatalf("4th scan (post-baseline): expected exit 0 (clean), got %d\noutput:\n%s", code, out)
	}

	// diff must agree: no active drift.
	out, code = captureStdout(t, func() int { return run([]string{"diff", "target"}) })
	if code != ExitClean {
		t.Fatalf("diff: expected exit 0, got %d\noutput:\n%s", code, out)
	}
}

// TestCLI_AcceptClearsDrift exercises `accept` (single-port approval) as
// an alternative to `baseline`, and checks the same post-acceptance
// clean-scan regression.
func TestCLI_AcceptClearsDrift(t *testing.T) {
	newTestDB(t)
	host, port := listenOpenPort(t)
	portsFlag := itoa(port)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "target", host}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	scanArgs := []string{"scan", "target", "--ports", portsFlag, "--timeout", "50"}

	if _, code := captureStdout(t, func() int { return run(scanArgs) }); code != ExitPendingDrift {
		t.Fatalf("1st scan: expected exit %d, got %d", ExitPendingDrift, code)
	}
	if _, code := captureStdout(t, func() int { return run(scanArgs) }); code != ExitConfirmedDrift {
		t.Fatalf("2nd scan: expected exit %d, got %d", ExitConfirmedDrift, code)
	}

	out, code := captureStdout(t, func() int { return run([]string{"accept", "target", portsFlag}) })
	if code != ExitClean {
		t.Fatalf("accept: expected exit 0, got %d\noutput:\n%s", code, out)
	}

	out, code = captureStdout(t, func() int { return run(scanArgs) })
	if code != ExitClean {
		t.Fatalf("scan after accept: expected exit 0 (clean), got %d\noutput:\n%s", code, out)
	}
	out, code = captureStdout(t, func() int { return run(scanArgs) })
	if code != ExitClean {
		t.Fatalf("2nd scan after accept: expected exit 0 (clean), got %d\noutput:\n%s", code, out)
	}
}

// TestCLI_NoSaveDoesNotPersist checks that --no-save performs a scan but
// never writes a scan row, an observation, or triggers event tracking.
func TestCLI_NoSaveDoesNotPersist(t *testing.T) {
	newTestDB(t)
	host, port := listenOpenPort(t)
	portsFlag := itoa(port)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "target", host}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	out, code := captureStdout(t, func() int {
		return run([]string{"scan", "target", "--ports", portsFlag, "--timeout", "50", "--no-save", "--json"})
	})
	if code != ExitClean {
		t.Fatalf("--no-save scan: expected exit 0, got %d\noutput:\n%s", code, out)
	}
	var res output.ScanResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal scan --json: %v (output=%s)", err, out)
	}
	if res.Saved {
		t.Fatalf("expected Saved=false for --no-save scan, got %+v", res)
	}

	historyOut, code := captureStdout(t, func() int { return run([]string{"history", "target"}) })
	if code != ExitClean {
		t.Fatalf("history: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(historyOut), []byte("No scan history recorded")) {
		t.Fatalf("expected no scan history after --no-save, got %q", historyOut)
	}
}

// TestCLI_ScanUnknownAsset checks that scanning a never-registered asset
// fails with ExitError rather than silently doing nothing.
func TestCLI_ScanUnknownAsset(t *testing.T) {
	newTestDB(t)
	_, code := captureStdout(t, func() int { return run([]string{"scan", "ghost", "--ports", "22"}) })
	if code != ExitError {
		t.Fatalf("scan of unregistered asset: expected exit %d, got %d", ExitError, code)
	}
}

// TestCLI_CleanupRuns is a smoke test that `cleanup` runs cleanly against
// an empty database and reports a zero-work JSON report.
func TestCLI_CleanupRuns(t *testing.T) {
	newTestDB(t)
	out, code := captureStdout(t, func() int { return run([]string{"cleanup", "--retention-days", "30", "--json"}) })
	if code != ExitClean {
		t.Fatalf("cleanup: expected exit 0, got %d\noutput:\n%s", code, out)
	}
	var report struct {
		ScansDeleted  int64 `json:"scans_deleted"`
		EventsDeleted int64 `json:"events_deleted"`
		RetentionDays int   `json:"retention_days"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal cleanup --json: %v (output=%s)", err, out)
	}
	if report.ScansDeleted != 0 || report.EventsDeleted != 0 {
		t.Fatalf("expected a zero-work report against an empty DB, got %+v", report)
	}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
