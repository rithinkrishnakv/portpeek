// Package scanner implements PortPeek's lightweight TCP connect scanner.
//
// This is deliberately simple: it opens a TCP connection to each requested
// port and classifies the outcome. It does not attempt SYN scanning,
// evasion, timing games, or anything that requires raw sockets or elevated
// privileges. It is not, and is not trying to be, a replacement for Nmap.
package scanner

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// State is the outcome of probing a single TCP port.
type State string

const (
	StateOpen     State = "open"
	StateClosed   State = "closed"
	StateFiltered State = "filtered"
	StateTimeout  State = "timeout"
)

// Result is the raw outcome of probing one port, before any fingerprinting
// has been attempted.
type Result struct {
	Port  int
	Proto string
	State State
}

// Options controls scan behaviour.
type Options struct {
	Timeout     time.Duration
	Concurrency int
}

// Scan performs a TCP connect scan of host across the given ports and
// returns one Result per port, sorted by port number. It never mutates or
// sends anything beyond the TCP handshake itself (and, for refused/closed
// ports, the kernel's own RST) - no payload is written during scanning.
// Payload-level probing happens later, and only against ports found open,
// in the fingerprint package.
func Scan(ctx context.Context, host string, ports []int, opts Options) []Result {
	if opts.Timeout <= 0 {
		opts.Timeout = 1200 * time.Millisecond
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 64
	}

	results := make([]Result, len(ports))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(i, port int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = Result{
				Port:  port,
				Proto: "tcp",
				State: probe(ctx, host, port, opts.Timeout),
			}
		}(i, port)
	}

	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

func probe(ctx context.Context, host string, port int, timeout time.Duration) State {
	dialer := net.Dialer{Timeout: timeout}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		_ = conn.Close()
		return StateOpen
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	// Anything else (network unreachable, no route to host, permission
	// denied, host down) we conservatively call "filtered": we could not
	// get a definitive open/closed answer from this vantage point.
	return StateFiltered
}
