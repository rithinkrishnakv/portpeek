package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/config"
	"github.com/rithinkrishnakv/portpeek/internal/events"
	"github.com/rithinkrishnakv/portpeek/internal/fingerprint"
	"github.com/rithinkrishnakv/portpeek/internal/output"
	"github.com/rithinkrishnakv/portpeek/internal/scanner"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	portsSpec := fs.String("ports", "", "port specification, e.g. \"22,80,443\" or \"1-1000\" (default: common ports)")
	timeoutMs := fs.Int("timeout", config.DefaultTimeoutMillis, "per-port connect timeout in milliseconds")
	jsonOut := fs.Bool("json", false, "print results as JSON")
	quiet := fs.Bool("quiet", false, "suppress the observation table; only print the final summary line")
	noSave := fs.Bool("no-save", false, "perform a temporary scan without writing persistent state")
	confirmPublic := fs.Bool("confirm-public-target", false, "confirm, for this invocation only, scanning a target that resolves to a public (non-private) address")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: portpeek scan <asset> [--ports SPEC] [--timeout MS] [--json] [--quiet] [--no-save] [--confirm-public-target]")
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

	var ports []int
	if *portsSpec == "" {
		ports = config.DefaultPorts
	} else {
		p, err := scanner.ParsePortSpec(*portsSpec)
		if err != nil {
			errorf("invalid --ports: %v", err)
			return ExitError
		}
		ports = p
	}
	if *timeoutMs <= 0 {
		errorf("--timeout must be a positive number of milliseconds")
		return ExitError
	}
	timeout := time.Duration(*timeoutMs) * time.Millisecond

	st, ok := openStore()
	if !ok {
		return ExitError
	}
	defer st.Close()

	asset, ok := mustAsset(st, label)
	if !ok {
		return ExitError
	}

	ctx := context.Background()

	if !checkPublicTargetAllowed(ctx, asset, *confirmPublic) {
		return ExitError
	}

	startedAt := time.Now()

	results := scanner.Scan(ctx, asset.Host, ports, scanner.Options{
		Timeout:     timeout,
		Concurrency: config.DefaultConcurrency,
	})

	obs := make([]storage.Observation, 0, len(results))
	for _, r := range results {
		o := storage.Observation{
			Port:  r.Port,
			Proto: r.Proto,
			State: string(r.State),
		}
		if r.State == scanner.StateOpen {
			fp := fingerprint.Identify(ctx, asset.Host, r.Port, timeout)
			o.Service = strPtrIfSet(fp.Service)
			o.VersionInfo = strPtrIfSet(fp.VersionInfo)
			o.Banner = strPtrIfSet(fp.Banner)
			o.Confidence = strPtrIfSet(string(fp.Confidence))
			o.Evidence = strPtrIfSet(fp.Evidence)
		}
		obs = append(obs, o)
	}
	finishedAt := time.Now()
	vantage := config.Vantage()
	portsSpecRecorded := scanner.FormatPortSpec(ports)

	if *noSave {
		if *jsonOut {
			res := output.ScanResult{
				Asset:        asset.Label,
				Target:       asset.Host,
				Vantage:      vantage,
				Scanner:      config.ScannerID,
				StartedAt:    startedAt.UTC().Format(time.RFC3339),
				FinishedAt:   finishedAt.UTC().Format(time.RFC3339),
				PortsSpec:    portsSpecRecorded,
				Saved:        false,
				Observations: obsToJSONList(obs),
			}
			return writeJSONOrErr(res)
		}
		fakeScan := storage.Scan{Vantage: vantage}
		output.PrintScanHuman(os.Stdout, asset, fakeScan, obs, false, events.Summary{}, *quiet)
		return ExitClean
	}

	scan, err := st.CreateScan(asset.ID, startedAt, finishedAt, vantage, config.ScannerID, portsSpecRecorded)
	if err != nil {
		errorf("save scan: %v", err)
		return ExitError
	}
	if err := st.AddObservations(scan.ID, obs); err != nil {
		errorf("save observations: %v", err)
		return ExitError
	}

	summary, err := events.Reconcile(st, asset.ID, obs)
	if err != nil {
		errorf("reconcile events: %v", err)
		return ExitError
	}

	if *jsonOut {
		res := output.ScanResult{
			Asset:        asset.Label,
			Target:       asset.Host,
			Vantage:      vantage,
			Scanner:      config.ScannerID,
			StartedAt:    startedAt.UTC().Format(time.RFC3339),
			FinishedAt:   finishedAt.UTC().Format(time.RFC3339),
			PortsSpec:    portsSpecRecorded,
			Saved:        true,
			Observations: obsToJSONList(obs),
			NewEvents:    eventsToJSONList(append(append([]storage.Event{}, summary.NewlyPending...), summary.NewlyConfirmed...)),
		}
		code := writeJSONOrErr(res)
		if code != ExitClean {
			return code
		}
		return exitCodeForAsset(st, asset.ID)
	}

	output.PrintScanHuman(os.Stdout, asset, scan, obs, true, summary, *quiet)
	return exitCodeForAsset(st, asset.ID)
}

func strPtrIfSet(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func obsToJSONList(obs []storage.Observation) []output.ObservationJSON {
	out := make([]output.ObservationJSON, 0, len(obs))
	for _, o := range obs {
		out = append(out, output.ObsToJSON(o))
	}
	return out
}

func eventsToJSONList(evs []storage.Event) []output.EventJSON {
	out := make([]output.EventJSON, 0, len(evs))
	for _, e := range evs {
		out = append(out, output.EventToJSON(e))
	}
	return out
}

// exitCodeForAsset inspects the asset's current active events and returns
// the appropriate documented exit code.
func exitCodeForAsset(st *storage.Store, assetID int64) int {
	active, err := st.ListActiveEvents(assetID)
	if err != nil {
		errorf("load events: %v", err)
		return ExitError
	}
	if events.HasConfirmedDrift(active) {
		return ExitConfirmedDrift
	}
	if events.HasPendingDrift(active) {
		return ExitPendingDrift
	}
	return ExitClean
}
