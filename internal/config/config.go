// Package config holds PortPeek's default settings. Nothing here reaches
// the network or disk on its own; it is just shared constants and a small
// set of helpers for resolving the on-disk database location.
package config

import (
	"os"
	"path/filepath"
)

// Version is the PortPeek release version. Kept here (not internal/version)
// so it can be referenced from config-level defaults like the scanner
// identification string without an import cycle.
const Version = "0.1.0"

// DefaultTimeoutMillis is the default per-connection dial/read timeout used
// by both the scanner and the fingerprint probes when the user does not
// override it with --timeout.
const DefaultTimeoutMillis = 1200

// DefaultConcurrency bounds how many ports are probed in parallel during a
// scan. Kept modest by design: PortPeek is not trying to be a fast mass
// scanner, it is trying to be a polite, predictable exposure-tracking tool.
const DefaultConcurrency = 64

// DefaultRetentionDays controls how many days of non-baseline scan history
// `portpeek cleanup` keeps by default.
const DefaultRetentionDays = 30

// DefaultPorts is the port set used when the user does not pass --ports.
// It intentionally stays small and well-known rather than trying to
// approximate Nmap's "top 1000".
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 587, 993, 995, 1433, 1521, 2049, 3000,
	3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
}

// ScannerID identifies the scanner implementation and version recorded
// against every scan row, so observations can always be traced back to the
// code that produced them.
const ScannerID = "portpeek-tcpconnect/" + Version

// DBPath resolves the SQLite database path. It honours $PORTPEEK_DB first
// (useful for tests and for --no-save style isolation), then falls back to
// $XDG_DATA_HOME/portpeek/portpeek.db, then $HOME/.local/share/portpeek/portpeek.db.
func DBPath() (string, error) {
	if p := os.Getenv("PORTPEEK_DB"); p != "" {
		return p, nil
	}

	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}

	dir := filepath.Join(base, "portpeek")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "portpeek.db"), nil
}

// Vantage returns a best-effort label for "where this scan was run from".
// It never claims more than it knows: it reports the local machine's
// hostname, not whether that machine has a public or internal vantage
// point on the target network.
func Vantage() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}
