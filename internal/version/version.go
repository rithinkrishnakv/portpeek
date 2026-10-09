// Package version exposes build-time version information for PortPeek.
package version

import "github.com/rithinkrishnakv/portpeek/internal/config"

// Version is the current PortPeek release version.
const Version = config.Version

// GitCommit can be overridden at build time via:
//
//	go build -ldflags "-X github.com/rithinkrishnakv/portpeek/internal/version.GitCommit=$(git rev-parse --short HEAD)"
var GitCommit = "unknown"

// String returns a human-readable version string, e.g. "0.1.0 (abc1234)".
func String() string {
	if GitCommit == "" || GitCommit == "unknown" {
		return Version
	}
	return Version + " (" + GitCommit + ")"
}
