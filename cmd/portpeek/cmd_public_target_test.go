package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/safety"
	"github.com/rithinkrishnakv/portpeek/internal/scanner"
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

// --- Test seams -------------------------------------------------------
//
// These tests exercise the public-target safety gate's own decision and
// wiring logic (cmdScan, resolveScanTarget) without performing any real
// DNS resolution or outbound network connection: classifyFunc and
// scanFunc (see helpers.go and cmd_scan.go) are package-level
// indirections that default to the real safety.Classify/scanner.Scan in
// production and are substituted here for deterministic fakes. This is
// what lets the tests below run correctly with outbound networking
// unavailable, per CONTRIBUTING.md's "all tests are deterministic and run
// fully offline" policy - which the previous version of this file, using
// real addresses 8.8.8.8/8.8.4.4 that the public-target bypass tests then
// let reach the real scanner, did not actually honor.
//
// Separately, TestCLI_ScanRealIntegrationAgainstLocalListener and
// TestCLI_ScanNeverBlocksPrivateTargetRealResolution below use the real,
// unstubbed classifyFunc/scanFunc against a local 127.0.0.1 listener, so
// the production wiring itself - not just the fakes standing in for it -
// is proven to work, exactly as CONTRIBUTING.md's established pattern
// (local TCP listeners, no external network resource) describes.

// scanCall records one invocation of the scanFunc seam: the exact dial
// address and ports it was called with.
type scanCall struct {
	dialAddr string
	ports    []int
}

// stubScanner replaces scanFunc for the duration of the test with one that
// records every call (without performing any real network I/O) and
// returns result for each. It restores the real scanFunc on cleanup.
func stubScanner(t *testing.T, result []scanner.Result) *[]scanCall {
	t.Helper()
	orig := scanFunc
	calls := new([]scanCall)
	scanFunc = func(_ context.Context, dialAddr string, ports []int, _ scanner.Options) []scanner.Result {
		*calls = append(*calls, scanCall{dialAddr: dialAddr, ports: ports})
		return result
	}
	t.Cleanup(func() { scanFunc = orig })
	return calls
}

// stubClassifier replaces classifyFunc for the duration of the test with
// fn, counting how many times it's called, and restores the real
// classifyFunc on cleanup.
func stubClassifier(t *testing.T, fn func(ctx context.Context, host string) (safety.Classification, error)) *int {
	t.Helper()
	orig := classifyFunc
	calls := new(int)
	classifyFunc = func(ctx context.Context, host string) (safety.Classification, error) {
		*calls++
		return fn(ctx, host)
	}
	t.Cleanup(func() { classifyFunc = orig })
	return calls
}

// publicClassification and privateClassification build canned
// safety.Classification results. The addresses used for "public" tests
// are from RFC 5737's documentation ranges (TEST-NET-1/2/3), which are
// guaranteed never to be assigned to a real, reachable host - so even if
// a bug let one of these literal strings reach a real dial somewhere, it
// would fail immediately rather than actually contacting anything.
func publicClassification(host, addr string) (safety.Classification, error) {
	return safety.Classification{Host: host, Addrs: []net.IP{net.ParseIP(addr)}, AllPrivate: false}, nil
}

func privateClassification(host, addr string) (safety.Classification, error) {
	return safety.Classification{Host: host, Addrs: []net.IP{net.ParseIP(addr)}, AllPrivate: true}, nil
}

// --- Gate decision logic (fully stubbed, no network) -------------------

// TestCLI_ScanRefusesPublicTargetByDefault is the core regression test for
// the public-target safety gate: by default, scanning an asset whose host
// classifies as public must be refused, not silently performed - nothing
// should be persisted, and the scanner must never even be invoked.
func TestCLI_ScanRefusesPublicTargetByDefault(t *testing.T) {
	newTestDB(t)
	stubClassifier(t, func(_ context.Context, host string) (safety.Classification, error) {
		return publicClassification(host, "203.0.113.10")
	})
	scanCalls := stubScanner(t, []scanner.Result{{Port: 80, Proto: "tcp", State: scanner.StateClosed}})

	if _, code := captureStdout(t, func() int { return run([]string{"add", "pub", "public-asset.test"}) }); code != ExitClean {
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
	if len(*scanCalls) != 0 {
		t.Fatalf("expected the scanner to never be invoked when the gate refuses, got %d call(s): %+v", len(*scanCalls), *scanCalls)
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
	if len(*scanCalls) != 0 {
		t.Fatalf("expected the scanner to still never be invoked after a second refusal, got %d call(s)", len(*scanCalls))
	}
}

// TestCLI_ScanConfirmPublicTargetBypassesGateForOneInvocation covers the
// per-invocation --confirm-public-target bypass: the asset itself has no
// standing allowance, but passing the flag lets this one scan proceed past
// the safety gate (the refusal message must not appear, and the scanner
// must be invoked, dialing the classified address).
func TestCLI_ScanConfirmPublicTargetBypassesGateForOneInvocation(t *testing.T) {
	newTestDB(t)
	stubClassifier(t, func(_ context.Context, host string) (safety.Classification, error) {
		return publicClassification(host, "203.0.113.11")
	})
	scanCalls := stubScanner(t, []scanner.Result{{Port: 80, Proto: "tcp", State: scanner.StateClosed}})

	if _, code := captureStdout(t, func() int { return run([]string{"add", "pub", "public-asset.test"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	stderr, code := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "pub", "--ports", "80", "--timeout", "50", "--no-save", "--confirm-public-target"})
		})
		return c
	})
	if strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("expected --confirm-public-target to bypass the safety gate, but got refusal: %q", stderr)
	}
	if code != ExitClean {
		t.Fatalf("expected the confirmed scan to succeed, got exit %d (stderr=%q)", code, stderr)
	}
	if len(*scanCalls) != 1 || (*scanCalls)[0].dialAddr != "203.0.113.11" {
		t.Fatalf("expected exactly 1 scan dialing the classified address, got %+v", *scanCalls)
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
	if len(*scanCalls) != 1 {
		t.Fatalf("expected no additional scan on the refused 2nd invocation, got %d total calls", len(*scanCalls))
	}
}

// TestCLI_AllowPublicTargetCommandGrantsStandingBypass covers the
// persistent allowlist path end-to-end: `add --allow-public-target` at
// creation time, and `allow-public-target` / `allow-public-target --off`
// toggling it for an asset that already exists.
func TestCLI_AllowPublicTargetCommandGrantsStandingBypass(t *testing.T) {
	newTestDB(t)
	stubClassifier(t, func(_ context.Context, host string) (safety.Classification, error) {
		return publicClassification(host, "203.0.113.12")
	})
	stubScanner(t, []scanner.Result{{Port: 80, Proto: "tcp", State: scanner.StateClosed}})

	// Created with the flag already set.
	if _, code := captureStdout(t, func() int {
		return run([]string{"add", "pub1", "public-asset-1.test", "--allow-public-target"})
	}); code != ExitClean {
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
	if _, code := captureStdout(t, func() int {
		return run([]string{"add", "pub2", "public-asset-2.test"})
	}); code != ExitClean {
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
// Fully stubbed (no real resolution or dial) for speed and determinism;
// TestCLI_ScanNeverBlocksPrivateTargetRealResolution below covers the same
// property through the real, unstubbed classifyFunc/scanFunc.
func TestCLI_ScanNeverBlocksPrivateTarget(t *testing.T) {
	newTestDB(t)
	stubClassifier(t, func(_ context.Context, host string) (safety.Classification, error) {
		return privateClassification(host, "10.0.0.5")
	})
	scanCalls := stubScanner(t, []scanner.Result{{Port: 1, Proto: "tcp", State: scanner.StateClosed}})

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
	if code != ExitClean {
		t.Fatalf("expected a private-target scan to succeed, got exit %d (stderr=%q)", code, stderr)
	}
	if len(*scanCalls) != 1 {
		t.Fatalf("expected exactly 1 scan to proceed, got %d", len(*scanCalls))
	}
}

// --- DNS resolution consistency (requirement #2) ------------------------

// TestCLI_ScanDialsExactlyTheClassifiedAddress is the deterministic
// regression test for the DNS-resolution-consistency fix: cmdScan must
// resolve/classify an asset's host exactly once per invocation and then
// dial that same resolved address for the actual scan - never asset.Host
// itself, and never a second, independent re-resolution. Before this fix,
// the safety gate resolved the hostname once to decide allow/refuse, then
// handed the original hostname straight to scanner.Scan, which resolved
// it AGAIN on its own - a hostname whose DNS answer changed between those
// two independent resolutions (a classic TOCTOU/DNS-rebinding gap) could
// let a target that was classified private actually be scanned at a
// different, possibly public, address, or vice versa.
//
// The classified address here (198.51.100.42, from RFC 5737's TEST-NET-2
// documentation range) is deliberately different from the asset's
// configured hostname string, so this test fails loudly if cmdScan ever
// passes the raw hostname to the scanner instead of the resolved address.
func TestCLI_ScanDialsExactlyTheClassifiedAddress(t *testing.T) {
	newTestDB(t)
	const classifiedAddr = "198.51.100.42"
	classifyCalls := stubClassifier(t, func(_ context.Context, host string) (safety.Classification, error) {
		// AllPrivate: true just to reach the scanner without needing
		// --confirm-public-target in this test; the gate's allow/refuse
		// decision is covered separately above.
		return privateClassification(host, classifiedAddr)
	})
	scanCalls := stubScanner(t, []scanner.Result{{Port: 80, Proto: "tcp", State: scanner.StateClosed}})

	if _, code := captureStdout(t, func() int {
		return run([]string{"add", "host-based-asset", "some-hostname.example.test"})
	}); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	_, code := captureStdout(t, func() int {
		return run([]string{"scan", "host-based-asset", "--ports", "80", "--timeout", "50", "--no-save"})
	})
	if code != ExitClean {
		t.Fatalf("scan: expected exit 0, got %d", code)
	}

	if *classifyCalls != 1 {
		t.Fatalf("expected exactly 1 resolution per scan invocation (no redundant re-resolution), got %d", *classifyCalls)
	}
	if len(*scanCalls) != 1 {
		t.Fatalf("expected exactly 1 scanner invocation, got %d", len(*scanCalls))
	}
	if got := (*scanCalls)[0].dialAddr; got != classifiedAddr {
		t.Fatalf("expected the scan to dial the classified address %q, got %q - the original hostname must never be passed to the scanner directly", classifiedAddr, got)
	}
}

// --- Real, unstubbed integration (local listener only, no mocking) ------

// TestCLI_ScanRealIntegrationAgainstLocalListener exercises the real,
// unstubbed classifyFunc (safety.Classify) and scanFunc (scanner.Scan)
// end-to-end against a real local TCP listener on 127.0.0.1 - proving the
// actual production wiring works, not just the fakes standing in for it
// in the tests above. This makes no outbound network connection: the
// listener binds 127.0.0.1:0 (an OS-assigned loopback port), per
// CONTRIBUTING.md's established "local TCP listeners, no external network
// resource" pattern.
func TestCLI_ScanRealIntegrationAgainstLocalListener(t *testing.T) {
	newTestDB(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	if _, code := captureStdout(t, func() int { return run([]string{"add", "local", "127.0.0.1"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	var stdout string
	stderr, code := captureStderr(t, func() int {
		out, c := captureStdout(t, func() int {
			return run([]string{"scan", "local", "--ports", strconv.Itoa(port), "--timeout", "500", "--no-save", "--json", "--quiet"})
		})
		stdout = out
		return c
	})
	if code != ExitClean {
		t.Fatalf("real local scan: expected exit 0, got %d (stderr=%q)", code, stderr)
	}
	if strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("a loopback target must never be refused by the safety gate, got: %q", stderr)
	}

	var res output.ScanResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("decode scan JSON: %v (stdout=%s)", err, stdout)
	}
	if len(res.Observations) != 1 || res.Observations[0].State != "open" {
		t.Fatalf("expected the real local listener's port to be observed open, got %+v", res.Observations)
	}
}

// TestCLI_ScanNeverBlocksPrivateTargetRealResolution is
// TestCLI_ScanNeverBlocksPrivateTarget's counterpart using the real,
// unstubbed classifyFunc: an IP-literal private asset must never be
// refused. safety.Classify on an IP literal is a pure parse (see
// safety.go), so this performs no network resolution either - only the
// scan itself touches the network, and only loopback.
func TestCLI_ScanNeverBlocksPrivateTargetRealResolution(t *testing.T) {
	newTestDB(t)

	if _, code := captureStdout(t, func() int { return run([]string{"add", "loopback", "127.0.0.1"}) }); code != ExitClean {
		t.Fatalf("add: expected exit 0, got %d", code)
	}

	stderr, code := captureStderr(t, func() int {
		_, c := captureStdout(t, func() int {
			return run([]string{"scan", "loopback", "--ports", "1", "--timeout", "50", "--no-save"})
		})
		return c
	})
	if strings.Contains(stderr, refusalSnippet) {
		t.Fatalf("expected a loopback target to never be refused by the real safety gate, got: %q", stderr)
	}
	if code != ExitClean {
		t.Fatalf("expected the scan to complete cleanly, got exit %d (stderr=%q)", code, stderr)
	}
}
