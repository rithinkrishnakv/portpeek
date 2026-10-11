package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print the created asset as JSON")
	allowPublic := fs.Bool("allow-public-target", false, "persistently allow scanning this asset even if its host resolves to a public (non-private) address, without per-scan confirmation")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek add <label> <host> [--allow-public-target]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return ExitError
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return ExitError
	}
	label, host := fs.Arg(0), fs.Arg(1)

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	a, err := st.CreateAsset(label, host)
	if err != nil {
		if err == storage.ErrAlreadyExists {
			errorf("asset %q already exists", label)
		} else {
			errorf("create asset: %v", err)
		}
		return ExitError
	}

	if *allowPublic {
		if err := st.SetAllowPublicTarget(a.ID, true); err != nil {
			errorf("set allow-public-target: %v", err)
			return ExitError
		}
		a.AllowPublicTarget = true
	}

	if *jsonOut {
		return writeJSONOrErr(assetToJSON(a))
	}

	fmt.Printf("Added asset %q -> %s\n", a.Label, a.Host)
	fmt.Println("Next: portpeek scan " + a.Label)
	return ExitClean
}
