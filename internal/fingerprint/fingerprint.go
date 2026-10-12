// Package fingerprint implements PortPeek's lightweight, non-destructive
// service identification.
//
// Every probe here either reads what a service volunteers on connect (a
// banner) or sends a single, well-known, harmless protocol handshake byte
// sequence (an SSH identification read, an HTTP HEAD request, a Postgres
// SSLRequest, a Redis PING, ...). Nothing here attempts authentication,
// exploits a parser, or sends anything a legitimate, unauthenticated client
// of that protocol would not also send.
//
// PortPeek never claims more than it observed: every Result carries an
// explicit confidence level and the evidence that produced it.
package fingerprint

import (
	"context"
	"time"
)

// Confidence describes how sure PortPeek is about an identification.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Result is a single fingerprinting outcome for one open port.
type Result struct {
	// Service is a short family name, e.g. "SSH", "HTTP", "Redis".
	// "Unknown TCP service" is used when nothing could be identified.
	Service string
	// VersionInfo is an optional, specific version string extracted from
	// evidence (e.g. "OpenSSH 9.6"). Empty when no version was observed.
	VersionInfo string
	// Banner is the raw (truncated, sanitized) text evidence, when the
	// service sent one. May be empty for probe-based identifications
	// that do not involve a printable banner (e.g. Postgres SSLRequest).
	Banner string
	// Confidence states how sure PortPeek is.
	Confidence Confidence
	// Evidence is a short, human-readable explanation of what was
	// observed and why it supports this identification.
	Evidence string
}

// unknown is the result returned when no probe could identify the service.
func unknown(evidence string) Result {
	return Result{
		Service:    "Unknown TCP service",
		Confidence: ConfidenceLow,
		Evidence:   evidence,
	}
}

// portHints maps well-known ports to the family PortPeek should try first.
// This is purely an ordering optimization - every family below can still be
// identified on a non-standard port via the fallback chain in Identify.
var portHints = map[int]string{
	21:   "ftp",
	22:   "ssh",
	25:   "smtp",
	587:  "smtp",
	3306: "mysql",
	5432: "postgres",
	6379: "redis",
	443:  "https",
	8443: "https",
	80:   "http",
	8000: "http",
	8080: "http",
	3000: "http",
	9200: "http",
}

// fallbackOrder is the canonical order PortPeek tries banner/request-based
// families that are reasonably safe and cheap to attempt blindly, for ports
// it has no hint about. The three request-first database protocols
// (mysql, postgres, redis) are deliberately NOT included here: they are
// only attempted when the port number hints at them, so that PortPeek does
// not send database wire-protocol bytes to arbitrary unknown ports.
var fallbackOrder = []string{"ssh", "ftp", "smtp", "https", "http"}

// Identify attempts to determine what service is listening on
// dialAddr:port. It assumes the caller has already confirmed the port is
// open (e.g. via scanner.Scan); Identify performs its own fresh
// connection(s) for probing.
//
// dialAddr and sniHost are deliberately separate parameters:
//
//   - dialAddr is the literal address every connection this call makes is
//     actually dialed to. Callers that have already resolved and
//     classified a target (see internal/safety and cmd_scan.go's
//     public-target safety gate) should pass that already-resolved
//     address here - typically an IP literal - rather than a hostname, so
//     Identify performs no DNS resolution of its own and the address
//     fingerprinted is guaranteed to be the one the caller already
//     checked, not a freshly (and possibly differently) re-resolved one.
//   - sniHost is used only for protocol content that must stay
//     hostname-based regardless of which literal address the bytes are
//     sent to: the HTTP `Host:` header (httpProbe) and the TLS
//     ServerName / SNI extension (httpsProbe), both needed for correct
//     identification of a virtual-hosted service. For a target with no
//     separate hostname (a bare IP asset), callers should pass the same
//     value for both.
func Identify(ctx context.Context, dialAddr, sniHost string, port int, timeout time.Duration) Result {
	tried := make(map[string]bool)

	if hint, ok := portHints[port]; ok {
		if res, matched := safeProbeFamily(ctx, hint, dialAddr, sniHost, port, timeout); matched {
			return res
		}
		tried[hint] = true
	}

	for _, fam := range fallbackOrder {
		if tried[fam] {
			continue
		}
		tried[fam] = true
		if res, matched := safeProbeFamily(ctx, fam, dialAddr, sniHost, port, timeout); matched {
			return res
		}
	}

	if res, matched := safeGenericBannerProbe(ctx, dialAddr, port, timeout); matched {
		return res
	}

	return unknown("no identifying response received; service accepted a TCP connection but sent no recognizable banner")
}

// safeProbeFamily and safeGenericBannerProbe are panic-recovery boundaries
// around every individual probe. Every probe parses bytes volunteered by
// whatever is listening on the far end of the connection - untrusted,
// arbitrary, potentially malformed or deliberately hostile input. A
// defensive bug in any one probe's parsing (now or added later) must never
// take down the whole scan; a recovered panic is treated exactly like an
// ordinary "no match", and Identify simply moves on to the next family or
// the generic fallback, the same as it would for any other non-match.
func safeProbeFamily(ctx context.Context, family, dialAddr, sniHost string, port int, timeout time.Duration) (res Result, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			res, matched = Result{}, false
		}
	}()
	return probeFamily(ctx, family, dialAddr, sniHost, port, timeout)
}

func safeGenericBannerProbe(ctx context.Context, host string, port int, timeout time.Duration) (res Result, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			res, matched = Result{}, false
		}
	}()
	return genericBannerProbe(ctx, host, port, timeout)
}

// probeFamily dispatches to one protocol family's probe. Only the two
// HTTP(S) probes need sniHost (for the Host header / TLS SNI); every other
// family only ever dials dialAddr and never puts a hostname into protocol
// content, so they're passed dialAddr alone.
func probeFamily(ctx context.Context, family, dialAddr, sniHost string, port int, timeout time.Duration) (Result, bool) {
	switch family {
	case "ssh":
		return sshProbe(ctx, dialAddr, port, timeout)
	case "ftp":
		return ftpProbe(ctx, dialAddr, port, timeout)
	case "smtp":
		return smtpProbe(ctx, dialAddr, port, timeout)
	case "mysql":
		return mysqlProbe(ctx, dialAddr, port, timeout)
	case "postgres":
		return postgresProbe(ctx, dialAddr, port, timeout)
	case "redis":
		return redisProbe(ctx, dialAddr, port, timeout)
	case "https":
		return httpsProbe(ctx, dialAddr, sniHost, port, timeout)
	case "http":
		return httpProbe(ctx, dialAddr, sniHost, port, timeout)
	}
	return Result{}, false
}
