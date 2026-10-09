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

// Identify attempts to determine what service is listening on host:port.
// It assumes the caller has already confirmed the port is open (e.g. via
// scanner.Scan); Identify performs its own fresh connection(s) for probing.
func Identify(ctx context.Context, host string, port int, timeout time.Duration) Result {
	tried := make(map[string]bool)

	if hint, ok := portHints[port]; ok {
		if res, matched := probeFamily(ctx, hint, host, port, timeout); matched {
			return res
		}
		tried[hint] = true
	}

	for _, fam := range fallbackOrder {
		if tried[fam] {
			continue
		}
		tried[fam] = true
		if res, matched := probeFamily(ctx, fam, host, port, timeout); matched {
			return res
		}
	}

	if res, matched := genericBannerProbe(ctx, host, port, timeout); matched {
		return res
	}

	return unknown("no identifying response received; service accepted a TCP connection but sent no recognizable banner")
}

func probeFamily(ctx context.Context, family, host string, port int, timeout time.Duration) (Result, bool) {
	switch family {
	case "ssh":
		return sshProbe(ctx, host, port, timeout)
	case "ftp":
		return ftpProbe(ctx, host, port, timeout)
	case "smtp":
		return smtpProbe(ctx, host, port, timeout)
	case "mysql":
		return mysqlProbe(ctx, host, port, timeout)
	case "postgres":
		return postgresProbe(ctx, host, port, timeout)
	case "redis":
		return redisProbe(ctx, host, port, timeout)
	case "https":
		return httpsProbe(ctx, host, port, timeout)
	case "http":
		return httpProbe(ctx, host, port, timeout)
	}
	return Result{}, false
}
