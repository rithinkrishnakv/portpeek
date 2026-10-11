// Package safety implements PortPeek's guard against accidentally
// scanning a public (internet-routable) target. It does not replace the
// authorized-use policy documented in SECURITY.md and README.md - no
// automated check can verify authorization - but it catches the much more
// common accident: a typo'd IP, a host that resolves somewhere the user
// didn't expect, or a target added in a hurry without noticing it wasn't
// actually on a private network.
//
// This package is deliberately pure/offline: it classifies IP addresses
// using only the Go standard library's own RFC1918/RFC4193/loopback/
// link-local logic (net.IP's IsPrivate/IsLoopback/IsLinkLocal* methods),
// and resolves hostnames via the standard resolver. It makes no judgment
// about authorization, ownership, or intent - only about whether an
// address is the kind that is routable on the public internet at all.
package safety

import (
	"context"
	"fmt"
	"net"
)

// IsPrivateOrLoopback reports whether ip is not routable on the public
// internet: a loopback address (127.0.0.0/8, ::1), a private-use address
// (RFC1918 10/8, 172.16/12, 192.168/16, or RFC4193 fc00::/7), a
// link-local address (169.254.0.0/16, fe80::/10), or unspecified
// (0.0.0.0, ::). Anything else - including CGNAT (100.64.0.0/10, which
// Go's IsPrivate does not count as private, correctly: it is routable
// within an ISP's shared network and PortPeek has no way to know whether
// that counts as "safe" for a given user) - is treated as public.
func IsPrivateOrLoopback(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// Classification is the result of resolving and classifying a scan
// target.
type Classification struct {
	// Host is the literal input, unchanged.
	Host string
	// Addrs is every address Host resolved to (a single address if Host
	// was already a literal IP).
	Addrs []net.IP
	// AllPrivate is true only if every address in Addrs is
	// private/loopback/link-local. A hostname that resolves to a mix of
	// private and public addresses is NOT all-private, and is treated as
	// a public target - PortPeek scans whatever address the dialer
	// actually connects to, and it cannot assume that will be the private
	// one.
	AllPrivate bool
}

// Classify resolves host (an IP literal or a hostname) and classifies
// every address it resolves to. It uses the standard resolver, so for a
// hostname this does a real (local or upstream) DNS lookup - the same
// kind of lookup the scanner's own dialer will perform moments later.
func Classify(ctx context.Context, host string) (Classification, error) {
	c := Classification{Host: host}

	if ip := net.ParseIP(host); ip != nil {
		c.Addrs = []net.IP{ip}
		c.AllPrivate = IsPrivateOrLoopback(ip)
		return c, nil
	}

	var resolver net.Resolver
	addrs, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return c, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return c, fmt.Errorf("resolve %q: no addresses returned", host)
	}

	c.Addrs = addrs
	c.AllPrivate = true
	for _, a := range addrs {
		if !IsPrivateOrLoopback(a) {
			c.AllPrivate = false
			break
		}
	}
	return c, nil
}
