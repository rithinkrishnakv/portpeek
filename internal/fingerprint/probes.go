package fingerprint

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const maxBannerLen = 160

func dial(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// readLine reads a single line (up to maxBannerLen bytes) from conn,
// respecting the given deadline. No data is ever written to conn by this
// helper - it is for services that volunteer a banner on connect.
func readLine(conn net.Conn, timeout time.Duration) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReaderSize(conn, 512)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > maxBannerLen {
		line = line[:maxBannerLen]
	}
	return line, nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	return b.String()
}

// --- SSH ---------------------------------------------------------------

func sshProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	line, err := readLine(conn, timeout)
	if err != nil || !strings.HasPrefix(line, "SSH-") {
		return Result{}, false
	}
	line = sanitize(line)

	version := ""
	// SSH-2.0-OpenSSH_9.6 -> "OpenSSH 9.6"
	//
	// The software/version field after the second "-" is mandatory per
	// RFC 4253, but PortPeek must never assume a well-behaved remote
	// peer: a malformed or truncated banner (e.g. "SSH-2.0-" with
	// nothing after the final dash, or one trailing only whitespace)
	// must degrade to "no version extracted", never panic. The banner
	// itself is still captured as evidence either way.
	parts := strings.SplitN(line, "-", 3)
	if len(parts) == 3 {
		software := strings.TrimSpace(parts[2])
		if fields := strings.Fields(software); len(fields) > 0 {
			version = strings.ReplaceAll(fields[0], "_", " ")
		}
	}

	return Result{
		Service:     "SSH",
		VersionInfo: version,
		Banner:      line,
		Confidence:  ConfidenceHigh,
		Evidence:    "SSH identification string exchange",
	}, true
}

// --- FTP -----------------------------------------------------------------

func ftpProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	line, err := readLine(conn, timeout)
	if err != nil || !strings.HasPrefix(line, "220") {
		return Result{}, false
	}
	// Leave SMTP's "220 ... (ESMTP|SMTP) ..." banners to smtpProbe.
	if strings.Contains(strings.ToUpper(line), "SMTP") {
		return Result{}, false
	}
	line = sanitize(line)

	return Result{
		Service:    "FTP",
		Banner:     line,
		Confidence: ConfidenceHigh,
		Evidence:   "FTP 220 service-ready banner received",
	}, true
}

// --- SMTP ------------------------------------------------------------------

func smtpProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	line, err := readLine(conn, timeout)
	if err != nil || !strings.HasPrefix(line, "220") {
		return Result{}, false
	}
	if !strings.Contains(strings.ToUpper(line), "SMTP") {
		return Result{}, false
	}
	line = sanitize(line)

	return Result{
		Service:    "SMTP",
		Banner:     line,
		Confidence: ConfidenceHigh,
		Evidence:   "SMTP 220 greeting banner received",
	}, true
}

// --- MySQL / MariaDB ---------------------------------------------------

func mysqlProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		return Result{}, false
	}
	buf = buf[:n]

	// MySQL initial handshake packet: 3-byte length + 1-byte sequence,
	// then 1-byte protocol version, then a NUL-terminated server version
	// string. We only read and parse; we never respond, so the server
	// sees nothing beyond a normal TCP connect-and-read.
	protocolVersion := buf[4]
	if protocolVersion < 9 || protocolVersion > 10 {
		return Result{}, false
	}

	versionStr := ""
	for i := 5; i < len(buf); i++ {
		if buf[i] == 0 {
			versionStr = string(buf[5:i])
			break
		}
	}
	versionStr = sanitize(versionStr)
	if versionStr == "" {
		return Result{}, false
	}

	service := "MySQL/MariaDB"
	if strings.Contains(strings.ToLower(versionStr), "mariadb") {
		service = "MariaDB"
	}

	return Result{
		Service:     service,
		VersionInfo: versionStr,
		Confidence:  ConfidenceHigh,
		Evidence:    "MySQL protocol initial handshake packet received",
	}, true
}

// --- PostgreSQL ----------------------------------------------------------

func postgresProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	// The Postgres frontend/backend protocol's SSLRequest message: an
	// 8-byte packet (length=8, request code 80877103). This is the
	// standard, documented first message any Postgres client may send;
	// a real server always responds with a single 'S' or 'N' byte.
	req := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return Result{}, false
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return Result{}, false
	}

	switch resp[0] {
	case 'S':
		return Result{
			Service:    "PostgreSQL",
			Confidence: ConfidenceHigh,
			Evidence:   "PostgreSQL SSLRequest acknowledged (SSL supported)",
		}, true
	case 'N':
		return Result{
			Service:    "PostgreSQL",
			Confidence: ConfidenceHigh,
			Evidence:   "PostgreSQL SSLRequest acknowledged (SSL not supported)",
		}, true
	default:
		return Result{}, false
	}
}

// --- Redis -----------------------------------------------------------------

func redisProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return Result{}, false
	}

	line, err := readLine(conn, timeout)
	if err != nil {
		return Result{}, false
	}
	line = sanitize(line)

	switch {
	case strings.HasPrefix(line, "+PONG"):
		return Result{
			Service:    "Redis",
			Banner:     line,
			Confidence: ConfidenceHigh,
			Evidence:   "Redis protocol PING -> PONG",
		}, true
	case strings.HasPrefix(line, "-NOAUTH"):
		return Result{
			Service:    "Redis",
			Banner:     line,
			Confidence: ConfidenceHigh,
			Evidence:   "Redis protocol PING rejected with NOAUTH (authentication required)",
		}, true
	default:
		return Result{}, false
	}
}

// --- HTTPS (TLS) -----------------------------------------------------------

func httpsProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// InsecureSkipVerify is intentional and scoped to fingerprinting only:
	// PortPeek is identifying what is listening, not asserting that its
	// certificate is trustworthy. No certificate contents are trusted or
	// acted on beyond "a TLS handshake completed".
	tlsConn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 - fingerprint only, see comment above
	})
	_ = dialCtx
	if err != nil {
		return Result{}, false
	}
	defer tlsConn.Close()

	evidence := "TLS handshake completed"
	server := ""
	if s, ok := trySimpleHTTPRequest(tlsConn, host, timeout); ok {
		server = s
		evidence = "TLS handshake completed; HTTP response observed over TLS"
	}

	return Result{
		Service:     "HTTPS",
		VersionInfo: server,
		Confidence:  ConfidenceHigh,
		Evidence:    evidence,
	}, true
}

// --- HTTP ------------------------------------------------------------------

func httpProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	server, ok := trySimpleHTTPRequest(conn, host, timeout)
	if !ok {
		return Result{}, false
	}

	return Result{
		Service:     "HTTP",
		VersionInfo: server,
		Confidence:  ConfidenceHigh,
		Evidence:    "HTTP response received to HEAD request",
	}, true
}

// trySimpleHTTPRequest sends a minimal, read-only HEAD request and looks
// for an "HTTP/" status line in the reply. It returns the Server header
// value, if present. This is the same request any browser or health check
// makes; it never writes to any resource on the target.
func trySimpleHTTPRequest(conn net.Conn, host string, timeout time.Duration) (string, bool) {
	req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: PortPeek/0.1\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", false
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReaderSize(conn, 1024)
	status, err := r.ReadString('\n')
	if err != nil && status == "" {
		return "", false
	}
	if !strings.HasPrefix(status, "HTTP/") {
		return "", false
	}

	server := ""
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" || err != nil {
			break
		}
		// Find the header's name/value separator in the *original*
		// line and compare case-insensitively, rather than slicing the
		// original by the byte-length of a lowercased literal: under
		// full Unicode case folding a single character can lower into
		// more bytes than it started as (e.g. certain accented
		// uppercase letters), which would make a fixed-offset slice of
		// a hostile, non-ASCII header line panic with an out-of-range
		// index. A found colon index is always a valid bound for the
		// string it was found in, so this can never panic.
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		if strings.EqualFold(line[:idx], "server") {
			server = sanitize(strings.TrimSpace(line[idx+1:]))
			if len(server) > maxBannerLen {
				server = server[:maxBannerLen]
			}
		}
	}
	return server, true
}

// --- Generic fallback --------------------------------------------------

// genericBannerProbe connects and reads whatever a service volunteers,
// without sending anything. Used as a last resort for unrecognized
// services that still emit a banner on connect.
func genericBannerProbe(ctx context.Context, host string, port int, timeout time.Duration) (Result, bool) {
	conn, err := dial(ctx, host, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return Result{}, false
	}

	banner := sanitize(strings.TrimSpace(string(buf[:n])))
	if banner == "" {
		return Result{}, false
	}

	return Result{
		Service:    "Unknown TCP service",
		Banner:     banner,
		Confidence: ConfidenceLow,
		Evidence:   "unsolicited banner observed on connect; service family not recognized",
	}, true
}
