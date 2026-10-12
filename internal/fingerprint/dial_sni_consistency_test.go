package fingerprint

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// These are the deterministic regression tests for keeping the TCP dial
// target and the hostname used in protocol content (HTTP's Host header,
// TLS's SNI) independently controllable via Identify's dialAddr/sniHost
// parameters - see Identify's doc comment in fingerprint.go and
// docs/design.md's "DNS resolution consistency" section for why this
// split exists: cmd_scan.go resolves an asset's host once, classifies it
// for the public-target safety gate, and then dials that exact resolved
// address for every probe, while still needing HTTP/TLS probes to use the
// asset's original hostname so a virtual-hosted service is identified
// correctly.
//
// sniHost below is deliberately a .test hostname (reserved by RFC 2606,
// guaranteed never to resolve) that is never actually dialed in a
// correct implementation. If a probe ever dialed sniHost instead of
// dialAddr, the probe would fail outright - nothing is listening at an
// unresolvable name - so a passing test here is also regression coverage
// that dialing genuinely goes to dialAddr, never sniHost. No real or
// external network access is used anywhere in this file.
const unresolvableSNIHost = "internal-asset.test"

func TestHTTPProbeUsesSNIHostForHostHeaderNotDialAddr(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	captured := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- ""
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		hostHeader := ""
		for {
			line, err := r.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
			if line == "" || err != nil {
				break
			}
			if idx := strings.IndexByte(line, ':'); idx > 0 && strings.EqualFold(line[:idx], "host") {
				hostHeader = strings.TrimSpace(line[idx+1:])
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: test-server\r\n\r\n"))
		captured <- hostHeader
	}()

	// dialAddr is the real, reachable local listener; sniHost is a
	// distinct, deliberately unresolvable hostname that must still end up
	// in the Host header.
	res, ok := httpProbe(context.Background(), "127.0.0.1", unresolvableSNIHost, port, testTimeout)
	if !ok || res.Service != "HTTP" {
		t.Fatalf("expected a matched HTTP probe (which also proves dialing used dialAddr, not the unresolvable sniHost), got %+v ok=%v", res, ok)
	}

	select {
	case got := <-captured:
		if got != unresolvableSNIHost {
			t.Fatalf("expected Host header %q (sniHost), got %q", unresolvableSNIHost, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the test server to capture the request")
	}
}

// selfSignedTLSListener starts a local TLS listener on 127.0.0.1 with a
// fresh, ephemeral, self-signed certificate generated in-process - no
// external files, no real CA, no network access.
func selfSignedTLSListener(t *testing.T) (net.Listener, int, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "portpeek-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	return ln, ln.Addr().(*net.TCPAddr).Port, cfg
}

func TestHTTPSProbeUsesSNIHostForTLSServerNameNotDialAddr(t *testing.T) {
	ln, port, cfg := selfSignedTLSListener(t)
	defer ln.Close()

	capturedSNI := make(chan string, 1)
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		capturedSNI <- hello.ServerName
		return nil, nil // nil, nil => use cfg itself for this handshake
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, cfg)
		defer tlsConn.Close()
		_ = tlsConn.Handshake()
		// No HTTP response is sent: httpsProbe reports HTTPS from a
		// completed handshake alone, and its optional follow-up HTTP
		// request simply times out harmlessly if nothing answers.
	}()

	// dialAddr is the real, reachable local TLS listener; sniHost is a
	// distinct, deliberately unresolvable hostname that must still be the
	// one sent as the TLS ServerName (SNI), not dialAddr.
	res, ok := httpsProbe(context.Background(), "127.0.0.1", unresolvableSNIHost, port, testTimeout)
	if !ok || res.Service != "HTTPS" {
		t.Fatalf("expected a matched HTTPS probe (which also proves dialing used dialAddr, not the unresolvable sniHost), got %+v ok=%v", res, ok)
	}

	select {
	case got := <-capturedSNI:
		if got != unresolvableSNIHost {
			t.Fatalf("expected TLS ServerName (SNI) %q (sniHost), got %q", unresolvableSNIHost, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the test server to observe the ClientHello")
	}
}

// Note: probeFamily's dispatch of dialAddr/sniHost to httpProbe/httpsProbe
// (fingerprint.go) is a direct, untransformed parameter pass-through with
// no logic of its own, so the two direct tests above are deliberately not
// duplicated through the full Identify() entry point as well: doing so
// would mean either binding a fixed, hinted port (8080 etc.), which the
// existing Redis test in fingerprint_test.go already explains is not
// parallel-test-safe, or a considerably more elaborate fake server that
// distinguishes probe families by sniffing their first bytes - complexity
// this specific regression does not need, since there is no
// family-dependent branching between Identify's parameters and
// httpProbe/httpsProbe's for these tests to miss.
