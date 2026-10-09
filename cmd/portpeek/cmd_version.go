package main

import (
	"fmt"

	"github.com/rithinkrishnakv/portpeek/internal/version"
)

func cmdVersion(_ []string) int {
	fmt.Printf("portpeek %s\n", version.String())
	return ExitClean
}
