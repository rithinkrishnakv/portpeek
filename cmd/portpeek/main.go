// Command portpeek is a local-first network exposure changelog:
// scan -> observe -> remember -> compare -> explain.
//
// See README.md for the full command reference. Only scan systems you own
// or have explicit permission to assess.
package main

import (
	"fmt"
	"os"
)

// Exit codes, documented in README.md and stable across releases.
const (
	ExitClean          = 0
	ExitConfirmedDrift = 1
	ExitError          = 2
	ExitPendingDrift   = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return ExitError
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "add":
		return cmdAdd(rest)
	case "list":
		return cmdList(rest)
	case "scan":
		return cmdScan(rest)
	case "baseline":
		return cmdBaseline(rest)
	case "diff":
		return cmdDiff(rest)
	case "accept":
		return cmdAccept(rest)
	case "history":
		return cmdHistory(rest)
	case "remove":
		return cmdRemove(rest)
	case "cleanup":
		return cmdCleanup(rest)
	case "version", "-v", "--version":
		return cmdVersion(rest)
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return ExitClean
	default:
		fmt.Fprintf(os.Stderr, "portpeek: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		return ExitError
	}
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `PortPeek - a local-first network exposure changelog

  Scan -> Observe -> Remember -> Compare -> Explain

USAGE
  portpeek <command> [arguments]

COMMANDS
  add <label> <host>        Register a new asset
  list                      List registered assets
  scan <asset>               Scan an asset and record observations
  baseline <asset>          Accept the current observed state as expected
  diff <asset>               Compare the latest scan against expected state
  accept <asset> <port>     Approve a single port as expected
  history <asset>           Show scan history for an asset
  remove <asset>             Remove an asset and all its recorded data
  cleanup                    Prune old scan history beyond the retention window
  version                    Print the PortPeek version
  help                       Show this help text

Run "portpeek <command> --help" for command-specific flags.

Only scan systems you own or have explicit permission to assess.
`)
}
