package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

// listenLocal opens a listener on an OS-assigned free port on 127.0.0.1 and
// returns it along with the chosen port number. Using port 0 avoids any
// reliance on a specific port being free, keeping the test deterministic
// and independent of the host environment.
func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	return ln, addr.Port
}

func TestScanDetectsOpenPort(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()

	// Accept (and immediately drop) any connections so the scanner's
	// connect-and-close doesn't hang the listener.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	results := Scan(context.Background(), "127.0.0.1", []int{port}, Options{
		Timeout:     500 * time.Millisecond,
		Concurrency: 4,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State != StateOpen {
		t.Fatalf("expected open, got %s", results[0].State)
	}
	if results[0].Port != port {
		t.Fatalf("expected port %d, got %d", port, results[0].Port)
	}
}

func TestScanDetectsClosedPort(t *testing.T) {
	// Bind, record the port, then close immediately: nothing is listening
	// there anymore, so the kernel will send a RST/refuse the connect.
	ln, port := listenLocal(t)
	ln.Close()

	results := Scan(context.Background(), "127.0.0.1", []int{port}, Options{
		Timeout:     500 * time.Millisecond,
		Concurrency: 4,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State != StateClosed {
		t.Fatalf("expected closed, got %s", results[0].State)
	}
}

func TestScanMultiplePortsSortedAndComplete(t *testing.T) {
	ln1, p1 := listenLocal(t)
	defer ln1.Close()
	go acceptAndDrop(ln1)

	ln2, p2 := listenLocal(t)
	ln2.Close() // closed port

	ports := []int{p2, p1} // deliberately unsorted input
	results := Scan(context.Background(), "127.0.0.1", ports, Options{
		Timeout:     500 * time.Millisecond,
		Concurrency: 4,
	})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Output must be sorted by port ascending, regardless of input order.
	if results[0].Port > results[1].Port {
		t.Fatalf("results not sorted by port: %v", results)
	}

	states := map[int]State{results[0].Port: results[0].State, results[1].Port: results[1].State}
	if states[p1] != StateOpen {
		t.Errorf("port %d: expected open, got %s", p1, states[p1])
	}
	if states[p2] != StateClosed {
		t.Errorf("port %d: expected closed, got %s", p2, states[p2])
	}
}

func TestScanNonOpenClassification(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation,
	// never routable to a real host. What a connect attempt there
	// produces depends on the network path - a real network will often
	// let it hang until our timeout fires, or return an ICMP
	// unreachable ("filtered"); a restrictive egress proxy (as in this
	// project's own sandboxed build/test environment) may reject it
	// immediately instead. All three are valid, non-"open" classifications;
	// what matters is that PortPeek never reports an unroutable address
	// as open, and that it always returns a single, specific state rather
	// than hanging indefinitely.
	start := time.Now()
	results := Scan(context.Background(), "192.0.2.1", []int{80}, Options{
		Timeout:     300 * time.Millisecond,
		Concurrency: 1,
	})
	elapsed := time.Since(start)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State == StateOpen {
		t.Fatalf("unroutable test address must never be reported open")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("scan took %s, should have resolved near the configured timeout", elapsed)
	}
}

func acceptAndDrop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}
