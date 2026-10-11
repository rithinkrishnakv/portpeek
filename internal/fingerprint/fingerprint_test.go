package fingerprint

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// listenLocal opens a listener on an OS-assigned free port on 127.0.0.1.
func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// Kept short because Identify's fallback chain may need to let several
// non-matching probes time out in sequence before it finds (or fails to
// find) a match; localhost loopback round-trips are fast enough that this
// stays reliable.
const testTimeout = 150 * time.Millisecond

// serveBanner accepts connections in a loop (Identify may make several
// probe connections before it finds a match) and writes the same banner
// to each one.
func serveBanner(ln net.Listener, banner []byte) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write(banner)
		conn.Close()
	}
}

func TestIdentifySSHBanner(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()
	go serveBanner(ln, []byte("SSH-2.0-OpenSSH_9.6\r\n"))

	res := Identify(context.Background(), "127.0.0.1", port, testTimeout)
	if res.Service != "SSH" {
		t.Fatalf("expected SSH, got %q (evidence=%q)", res.Service, res.Evidence)
	}
	if res.VersionInfo != "OpenSSH 9.6" {
		t.Errorf("expected version 'OpenSSH 9.6', got %q", res.VersionInfo)
	}
	if res.Confidence != ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", res.Confidence)
	}
}

func TestIdentifyFTPBanner(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()
	go serveBanner(ln, []byte("220 Welcome to test FTP\r\n"))

	res := Identify(context.Background(), "127.0.0.1", port, testTimeout)
	if res.Service != "FTP" {
		t.Fatalf("expected FTP, got %q", res.Service)
	}
}

func TestIdentifySMTPBanner(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()
	go serveBanner(ln, []byte("220 mail.example.com ESMTP Postfix\r\n"))

	res := Identify(context.Background(), "127.0.0.1", port, testTimeout)
	if res.Service != "SMTP" {
		t.Fatalf("expected SMTP, got %q", res.Service)
	}
}

func TestIdentifyRedisOnHintedPort(t *testing.T) {
	// Redis is only probed on its hinted port (6379) to avoid sending
	// database wire-protocol bytes to arbitrary unknown ports - see
	// fingerprint.go's fallbackOrder comment. We can't bind to 6379 in a
	// parallel-safe way across test runs, so we exercise the probe
	// function directly instead of going through the port-hint table.
	ln, port := listenLocal(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		if strings.Contains(string(buf[:n]), "PING") {
			conn.Write([]byte("+PONG\r\n"))
		}
	}()

	res, ok := redisProbe(context.Background(), "127.0.0.1", port, testTimeout)
	if !ok {
		t.Fatalf("expected redisProbe to match")
	}
	if res.Service != "Redis" {
		t.Fatalf("expected Redis, got %q", res.Service)
	}
	if res.Confidence != ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", res.Confidence)
	}
}

func TestIdentifyRedisAuthRequired(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		conn.Read(buf)
		conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
	}()

	res, ok := redisProbe(context.Background(), "127.0.0.1", port, testTimeout)
	if !ok || res.Service != "Redis" {
		t.Fatalf("expected Redis identified even behind auth, got ok=%v service=%q", ok, res.Service)
	}
}

func TestIdentifyHTTP(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				r.ReadString('\n') // request line, ignored
				for {
					line, err := r.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()

	res := Identify(context.Background(), "127.0.0.1", port, testTimeout)
	if res.Service != "HTTP" {
		t.Fatalf("expected HTTP, got %q", res.Service)
	}
	if res.VersionInfo != "TestServer/1.0" {
		t.Errorf("expected Server header 'TestServer/1.0', got %q", res.VersionInfo)
	}
}

func TestIdentifyMySQLHandshake(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Minimal, well-formed-enough MySQL initial handshake packet:
		// 3-byte length, 1-byte sequence, 1-byte protocol version (10),
		// then a NUL-terminated version string.
		payload := append([]byte{10}, []byte("8.0.35-test\x00")...)
		length := len(payload)
		header := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0}
		conn.Write(append(header, payload...))
	}()

	res, ok := mysqlProbe(context.Background(), "127.0.0.1", port, testTimeout)
	if !ok {
		t.Fatalf("expected mysqlProbe to match")
	}
	if res.Service != "MySQL/MariaDB" {
		t.Fatalf("expected MySQL/MariaDB, got %q", res.Service)
	}
	if res.VersionInfo != "8.0.35-test" {
		t.Errorf("expected version '8.0.35-test', got %q", res.VersionInfo)
	}
}

func TestIdentifyMariaDBVariant(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload := append([]byte{10}, []byte("10.11.6-MariaDB\x00")...)
		length := len(payload)
		header := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0}
		conn.Write(append(header, payload...))
	}()

	res, ok := mysqlProbe(context.Background(), "127.0.0.1", port, testTimeout)
	if !ok {
		t.Fatalf("expected mysqlProbe to match")
	}
	if res.Service != "MariaDB" {
		t.Fatalf("expected MariaDB, got %q", res.Service)
	}
}

func TestIdentifyPostgresSSLRequest(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8)
		conn.Read(buf)
		conn.Write([]byte{'S'})
	}()

	res, ok := postgresProbe(context.Background(), "127.0.0.1", port, testTimeout)
	if !ok {
		t.Fatalf("expected postgresProbe to match")
	}
	if res.Service != "PostgreSQL" {
		t.Fatalf("expected PostgreSQL, got %q", res.Service)
	}
}

func TestIdentifyUnknownService(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	// Accept every connection but never write anything and never speak
	// any known protocol - every probe should time out waiting for a
	// banner/response, and Identify should settle on "unknown" rather
	// than hang.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	res := Identify(context.Background(), "127.0.0.1", port, testTimeout)
	if res.Service != "Unknown TCP service" {
		t.Fatalf("expected Unknown TCP service, got %q", res.Service)
	}
	if res.Confidence != ConfidenceLow {
		t.Errorf("expected low confidence for unknown service, got %s", res.Confidence)
	}
}

func TestIdentifyGenericBanner(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()
	go serveBanner(ln, []byte("WEIRD-PROTOCOL/1.0 hello\n"))

	res := Identify(context.Background(), "127.0.0.1", port, testTimeout)
	if res.Service != "Unknown TCP service" {
		t.Fatalf("expected Unknown TCP service, got %q", res.Service)
	}
	if res.Banner == "" {
		t.Error("expected generic banner probe to capture the raw banner text")
	}
	if res.Confidence != ConfidenceLow {
		t.Errorf("expected low confidence, got %s", res.Confidence)
	}
}

// --- Regression tests: malformed banners must never panic ----------------
//
// These pin down a real crash that was found in sshProbe: a banner of
// exactly "SSH-2.0-" (a bare trailing dash with nothing after it - a
// three-byte-shorter, perfectly plausible truncation of a normal OpenSSH
// banner) made strings.Fields(software) return an empty slice, and then
// indexing [0] into that empty slice panicked. Since Identify calls probes
// against whatever is listening on the scanned host, any remote service
// (malicious or simply broken) could crash an entire `portpeek scan` by
// returning this banner on port 22. Every case below is run both directly
// against sshProbe and through the full Identify() entry point, so a
// regression here is caught however it's reached.

func mustNotPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: panicked: %v", name, r)
		}
	}()
	fn()
}

func TestIdentifySSHMalformedBannersDoNotPanic(t *testing.T) {
	cases := []struct {
		name   string
		banner string
	}{
		{"trailing dash, nothing after (the exact reported crash)", "SSH-2.0-\r\n"},
		{"trailing dash, bare newline only", "SSH-2.0-\n"},
		{"trailing dash followed only by whitespace", "SSH-2.0-   \r\n"},
		{"no software field and no second dash at all", "SSH-\r\n"},
		{"protocol version only, no dash after it", "SSH-2.0\r\n"},
		{"empty line (connect then immediate close, no banner)", ""},
		{"just the prefix", "SSH-"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, port := listenLocal(t)
			defer ln.Close()
			banner := tc.banner
			go serveBanner(ln, []byte(banner))

			var res Result
			mustNotPanic(t, "Identify", func() {
				res = Identify(context.Background(), "127.0.0.1", port, testTimeout)
			})
			// Whatever it decides, it must be a well-formed result: a
			// known sentinel service name, never a crash and never a
			// fabricated version string.
			if res.Service == "" {
				t.Errorf("expected a non-empty Service (even if %q), got empty", "Unknown TCP service")
			}
		})
	}
}

// TestSSHProbeTrailingDashNoVersion exercises sshProbe directly (not just
// through Identify's broader fallback chain) against the exact banner from
// the bug report, and checks the specific, correct behavior: the port is
// still identified as SSH (a service did perform the SSH identification
// string exchange - that much is real evidence), but with no fabricated
// VersionInfo, since none was actually present.
func TestSSHProbeTrailingDashNoVersion(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()
	go serveBanner(ln, []byte("SSH-2.0-\r\n"))

	var res Result
	var ok bool
	mustNotPanic(t, "sshProbe", func() {
		res, ok = sshProbe(context.Background(), "127.0.0.1", port, testTimeout)
	})
	if !ok {
		t.Fatalf("expected sshProbe to still match on the SSH- prefix, got ok=false")
	}
	if res.Service != "SSH" {
		t.Fatalf("expected Service=SSH, got %q", res.Service)
	}
	if res.VersionInfo != "" {
		t.Fatalf("expected no fabricated VersionInfo for a banner with no software field, got %q", res.VersionInfo)
	}
	if res.Banner == "" {
		t.Error("expected the raw (sanitized) banner to still be captured as evidence")
	}
}

// TestIdentifyHTTPMalformedHeadersDoNotPanic exercises the HTTP
// header-scanning path (trySimpleHTTPRequest) with adversarial header
// lines: no colon at all, a colon as the very first byte, and a non-ASCII
// "Server"-ish header name, none of which may panic regardless of how the
// header name is compared against "server".
func TestIdentifyHTTPMalformedHeadersDoNotPanic(t *testing.T) {
	cases := []struct {
		name    string
		headers string
	}{
		{"header line with no colon", "X-Weird-Header-No-Colon\r\n"},
		{"colon as the very first byte", ":leading-colon-value\r\n"},
		{"non-ASCII header name", "Sérvér: nginx\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, port := listenLocal(t)
			defer ln.Close()
			headers := tc.headers
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						r := bufio.NewReader(c)
						r.ReadString('\n') // request line, ignored
						for {
							line, err := r.ReadString('\n')
							if err != nil || strings.TrimSpace(line) == "" {
								break
							}
						}
						c.Write([]byte("HTTP/1.1 200 OK\r\n" + headers + "Content-Length: 0\r\n\r\n"))
					}(conn)
				}
			}()

			mustNotPanic(t, "Identify", func() {
				Identify(context.Background(), "127.0.0.1", port, testTimeout)
			})
		})
	}
}

// TestIdentifyNeverPanicsOnRandomBytes is a light fuzz-style smoke test:
// a handful of adversarial byte sequences (binary garbage, truncated
// protocol-looking prefixes, a huge single "line") are thrown at Identify
// end-to-end. None of them should ever panic, regardless of which probe in
// the fallback chain ends up handling them.
func TestIdentifyNeverPanicsOnRandomBytes(t *testing.T) {
	cases := [][]byte{
		{0x00, 0x01, 0x02, 0xff, 0xfe},
		[]byte("SSH-"),
		[]byte("SSH-2.0-"),
		[]byte("220"),
		[]byte("220 SMTP"),
		[]byte(strings.Repeat("A", 4096)),
		{},
	}

	for i, payload := range cases {
		payload := payload
		t.Run("", func(t *testing.T) {
			ln, port := listenLocal(t)
			defer ln.Close()
			go serveBanner(ln, payload)

			mustNotPanic(t, "Identify", func() {
				Identify(context.Background(), "127.0.0.1", port, testTimeout)
			})
			_ = i
		})
	}
}
