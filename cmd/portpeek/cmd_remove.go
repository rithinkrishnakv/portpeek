package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func cmdRemove(args []string) int {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek remove <asset>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return ExitError
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return ExitError
	}
	label := fs.Arg(0)

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	if err := st.RemoveAsset(label); err != nil {
		if err == storage.ErrNotFound {
			errorf("no such asset %q", label)
		} else {
			errorf("remove asset: %v", err)
		}
		return ExitError
	}

	fmt.Printf("Removed asset %q and all its recorded data.\n", label)
	return ExitClean
}
