package main

import (
	"flag"
	"os"

	"github.com/rithinkrishnakv/portpeek/internal/output"
)

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print assets as JSON")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return ExitError
	}

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	assets, err := st.ListAssets()
	if err != nil {
		errorf("list assets: %v", err)
		return ExitError
	}

	if *jsonOut {
		out := make([]output.AssetJSON, 0, len(assets))
		for _, a := range assets {
			out = append(out, assetToJSON(a))
		}
		return writeJSONOrErr(out)
	}

	output.PrintAssetsHuman(os.Stdout, assets)
	return ExitClean
}
