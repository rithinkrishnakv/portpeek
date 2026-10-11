package safety

import (
	"context"
	"net"
	"testing"
)

// TestIsPrivateOrLoopback pins down the exact classification PortPeek's
// public-target guard relies on: every address kind that must NOT trigger
// the guard (loopback, RFC1918/RFC4193 private, link-local, unspecified),
// and - just as important - the address kinds that MUST still trigger it,
// including the deliberate CGNAT exception documented on the function
// itself.
func TestIsPrivateOrLoopback(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv6 loopback", "::1", true},
		{"RFC1918 10/8", "10.0.0.1", true},
		{"RFC1918 172.16/12", "172.16.5.4", true},
		{"RFC1918 172.16/12 upper bound", "172.31.255.254", true},
		{"RFC1918 192.168/16", "192.168.1.1", true},
		{"RFC4193 unique local", "fc00::1", true},
		{"IPv4 link-local", "169.254.1.1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv4 unspecified", "0.0.0.0", true},
		{"IPv6 unspecified", "::", true},
		{"public IPv4", "8.8.8.8", false},
		{"public IPv4 (Cloudflare)", "1.1.1.1", false},
		{"public IPv6", "2606:4700:4700::1111", false},
		// CGNAT is deliberately NOT treated as private - PortPeek has no
		// way to know whether a given user's CGNAT range should count as
		// "safe", so it is conservatively classified as public.
		{"CGNAT 100.64/10", "100.64.0.1", false},
		{"just outside 172.16/12", "172.32.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("test fixture %q did not parse as an IP", tt.ip)
			}
			if got := IsPrivateOrLoopback(ip); got != tt.want {
				t.Errorf("IsPrivateOrLoopback(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestClassifyIPLiteral covers Classify's fast path: when the host is
// already a literal IP address, no DNS resolution happens at all, so this
// is fully deterministic and offline.
func TestClassifyIPLiteral(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		wantAllPrivate bool
	}{
		{"private literal", "192.168.1.50", true},
		{"loopback literal", "127.0.0.1", true},
		{"public literal", "8.8.8.8", false},
		{"CGNAT literal is public", "100.64.0.1", false},
		{"IPv6 private literal", "fc00::5", true},
		{"IPv6 public literal", "2001:4860:4860::8888", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Classify(context.Background(), tt.host)
			if err != nil {
				t.Fatalf("Classify(%q): unexpected error: %v", tt.host, err)
			}
			if c.Host != tt.host {
				t.Errorf("Classification.Host = %q, want %q", c.Host, tt.host)
			}
			if len(c.Addrs) != 1 {
				t.Fatalf("expected exactly one address for an IP literal, got %v", c.Addrs)
			}
			if c.AllPrivate != tt.wantAllPrivate {
				t.Errorf("Classify(%q).AllPrivate = %v, want %v", tt.host, c.AllPrivate, tt.wantAllPrivate)
			}
		})
	}
}

// TestClassifyLoopbackHostname exercises the real hostname-resolution path
// (not the IP-literal fast path) against "localhost", which resolves via
// the system's hosts file/NSS stack without a real network round trip in
// virtually every environment, keeping this deterministic. If local
// resolution is unavailable in a given sandbox, the test skips rather than
// flaking.
func TestClassifyLoopbackHostname(t *testing.T) {
	c, err := Classify(context.Background(), "localhost")
	if err != nil {
		t.Skipf("local resolution of %q unavailable in this environment: %v", "localhost", err)
	}
	if len(c.Addrs) == 0 {
		t.Fatal("expected at least one resolved address for localhost")
	}
	if !c.AllPrivate {
		t.Errorf("expected localhost to resolve to only loopback/private addresses, got %v (AllPrivate=false)", c.Addrs)
	}
}

// TestClassifyHostnameResolutionFailure covers the error path using a
// cancelled context, which deterministically fails resolution without
// depending on any real (and possibly flaky, possibly network-blocked)
// DNS lookup.
func TestClassifyHostnameResolutionFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately, before Classify ever calls LookupIP

	_, err := Classify(ctx, "example-nonexistent-host-for-portpeek-tests.invalid")
	if err == nil {
		t.Fatal("expected Classify to return an error when resolution fails, got nil")
	}
}

// TestClassifyEmptyAddrsNeverReported is a defensive check that Classify
// never returns a zero-value Classification with no error - every Classify
// call either errors or returns at least one address, so callers (the
// scan-time safety gate) never have to handle an ambiguous empty-but-ok
// result.
func TestClassifyEmptyAddrsNeverReported(t *testing.T) {
	c, err := Classify(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Addrs) == 0 {
		t.Fatal("Classify returned no error but also no addresses")
	}
}
