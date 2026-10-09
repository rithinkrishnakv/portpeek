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
