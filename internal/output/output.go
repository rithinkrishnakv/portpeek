// Package output renders PortPeek's results, either as human-readable
// terminal text or as stable JSON for automation. The two are never
// mixed: JSON output contains no decoration, and human output never
// silently drops fields JSON would include.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/rithinkrishnakv/portpeek/internal/events"
	"github.com/rithinkrishnakv/portpeek/internal/storage"
)

// --- JSON-facing types ------------------------------------------------
//
// These are intentionally separate from the storage.* types: they are the
// documented, stable public JSON contract, decoupled from internal schema
// details.

type ObservationJSON struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	State       string `json:"state"`
	Service     string `json:"service,omitempty"`
	VersionInfo string `json:"version_info,omitempty"`
	Banner      string `json:"banner,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

type EventJSON struct {
	Kind        string  `json:"kind"`
	Port        int     `json:"port"`
	Protocol    string  `json:"protocol"`
	Status      string  `json:"status"`
	Details     string  `json:"details,omitempty"`
	FirstSeen   string  `json:"first_seen"`
	LastSeen    string  `json:"last_seen"`
	ConfirmedAt *string `json:"confirmed_at,omitempty"`
	ScanCount   int     `json:"scan_count"`
}

type ScanResult struct {
	Asset        string            `json:"asset"`
	Target       string            `json:"target"`
	Vantage      string            `json:"vantage"`
	Scanner      string            `json:"scanner"`
	StartedAt    string            `json:"started_at"`
	FinishedAt   string            `json:"finished_at"`
	PortsSpec    string            `json:"ports_spec"`
	Saved        bool              `json:"saved"`
	Observations []ObservationJSON `json:"observations"`
	NewEvents    []EventJSON       `json:"new_events,omitempty"`
}

type DiffResult struct {
	Asset          string      `json:"asset"`
	Target         string      `json:"target"`
	ScanID         int64       `json:"scan_id"`
	ScannedAt      string      `json:"scanned_at"`
	ConfirmedDrift []EventJSON `json:"confirmed_drift"`
	PendingDrift   []EventJSON `json:"pending_drift"`
	ExitCode       int         `json:"exit_code"`
}

type AssetJSON struct {
	Label     string `json:"label"`
	Host      string `json:"host"`
	CreatedAt string `json:"created_at"`
}

type ExpectedJSON struct {
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	Service    string `json:"service,omitempty"`
	AcceptedAt string `json:"accepted_at"`
	Note       string `json:"note,omitempty"`
}

// BaselineResultJSON is `baseline --json`'s output: the ports whose
// expected state was recorded or refreshed, the ports whose stale
// expected-open entry was removed because they were definitively observed
// closed in the scan baseline acted on, and the ports that were observed
// closed and had no prior expected-open entry to remove, but whose active
// drift events (if any - typically a confirmed PORT_CLOSED tracking an
// exposure that was never formally baselined) were accepted anyway.
type BaselineResultJSON struct {
	Asset             string         `json:"asset"`
	Baselined         []ExpectedJSON `json:"baselined"`
	RemovedPorts      []int          `json:"removed_ports,omitempty"`
	AcknowledgedPorts []int          `json:"acknowledged_ports,omitempty"`
}

type HistoryEntryJSON struct {
	ScanID       int64             `json:"scan_id"`
	StartedAt    string            `json:"started_at"`
	Vantage      string            `json:"vantage"`
	PortsSpec    string            `json:"ports_spec"`
	Observations []ObservationJSON `json:"observations,omitempty"`
}

// --- Conversion helpers -------------------------------------------------

func ObsToJSON(o storage.Observation) ObservationJSON {
	return ObservationJSON{
		Port:        o.Port,
		Protocol:    o.Proto,
		State:       o.State,
		Service:     deref(o.Service),
		VersionInfo: deref(o.VersionInfo),
		Banner:      deref(o.Banner),
		Confidence:  deref(o.Confidence),
		Evidence:    deref(o.Evidence),
	}
}

func EventToJSON(e storage.Event) EventJSON {
	var confirmed *string
	if e.ConfirmedAt != nil {
		s := e.ConfirmedAt.Format(time.RFC3339)
		confirmed = &s
	}
	return EventJSON{
		Kind:        e.Kind,
		Port:        e.Port,
		Protocol:    e.Proto,
		Status:      e.Status,
		Details:     deref(e.Details),
		FirstSeen:   e.FirstSeen.Format(time.RFC3339),
		LastSeen:    e.LastSeen.Format(time.RFC3339),
		ConfirmedAt: confirmed,
		ScanCount:   e.ScanCount,
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// WriteJSON marshals v as indented, stable JSON to w.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- Human-readable rendering --------------------------------------------

// PrintScanHuman renders a scan's results in the README's terminal style.
func PrintScanHuman(w io.Writer, asset storage.Asset, scan storage.Scan, obs []storage.Observation, saved bool, summary events.Summary, quiet bool) {
	if !quiet {
		fmt.Fprintln(w, "PortPeek")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Asset: %s\n", asset.Label)
		fmt.Fprintf(w, "Target: %s\n", asset.Host)
		fmt.Fprintf(w, "Observed from: %s\n", scan.Vantage)
		if !saved {
			fmt.Fprintln(w, "(temporary scan - not saved, --no-save)")
		}
		fmt.Fprintln(w)
	}

	open := make([]storage.Observation, 0, len(obs))
	var closedN, filteredN, timeoutN int
	for _, o := range obs {
		switch o.State {
		case "open":
			open = append(open, o)
		case "closed":
			closedN++
		case "filtered":
			filteredN++
		case "timeout":
			timeoutN++
		}
	}

	if !quiet {
		if len(open) == 0 {
			fmt.Fprintln(w, "No open ports observed.")
		}
		for _, o := range open {
			svc := deref(o.Service)
			if svc == "" {
				svc = "-"
			}
			line := fmt.Sprintf("%-8s OPEN   %-10s", fmt.Sprintf("%d/%s", o.Port, o.Proto), svc)
			if ver := deref(o.VersionInfo); ver != "" {
				line += " " + ver
			}
			fmt.Fprintln(w, line)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%d open, %d closed, %d filtered, %d timeout (of %d ports checked)\n",
			len(open), closedN, filteredN, timeoutN, len(obs))
	}

	printEventSummary(w, summary, quiet)
}

func printEventSummary(w io.Writer, summary events.Summary, quiet bool) {
	if quiet {
		return
	}
	fmt.Fprintln(w)

	any := false
	for _, e := range summary.NewlyConfirmed {
		any = true
		printEventBlock(w, e, "⚠ ")
	}
	for _, e := range summary.NewlyPending {
		any = true
		fmt.Fprintf(w, "• %s on port %d/%s observed for the first time - will confirm on next scan if it persists.\n",
			humanKind(e.Kind), e.Port, e.Proto)
	}
	for _, e := range summary.Resolved {
		any = true
		fmt.Fprintf(w, "✓ %s on port %d/%s has resolved.\n", humanKind(e.Kind), e.Port, e.Proto)
	}
	for _, e := range summary.Cancelled {
		any = true
		fmt.Fprintf(w, "· %s on port %d/%s was only observed once and did not persist - not confirmed.\n",
			humanKind(e.Kind), e.Port, e.Proto)
	}

	if !any && len(summary.StillConfirmed) == 0 && len(summary.StillPending) == 0 {
		fmt.Fprintln(w, "No confirmed drift.")
		return
	}
	for _, e := range summary.StillConfirmed {
		printEventBlock(w, e, "⚠ ")
	}
	for _, e := range summary.StillPending {
		fmt.Fprintf(w, "• %s on port %d/%s still pending confirmation.\n", humanKind(e.Kind), e.Port, e.Proto)
	}
}

func printEventBlock(w io.Writer, e storage.Event, prefix string) {
	fmt.Fprintf(w, "%s%s\n\n", prefix, humanKindHeadline(e.Kind))
	fmt.Fprintf(w, "Port: %d/%s\n", e.Port, e.Proto)
	if e.Details != nil && *e.Details != "" {
		fmt.Fprintf(w, "%s\n", *e.Details)
	}
	fmt.Fprintf(w, "Status: %s\n\n", e.Status)
}

func humanKind(kind string) string {
	switch kind {
	case storage.EventNewPort:
		return "new exposure"
	case storage.EventPortClosed:
		return "port closed"
	case storage.EventServiceChanged:
		return "service change"
	case storage.EventServiceDisappeared:
		return "service disappeared"
	case storage.EventExpectedServiceMissing:
		return "expected service missing"
	default:
		return kind
	}
}

func humanKindHeadline(kind string) string {
	switch kind {
	case storage.EventNewPort:
		return "NEW EXPOSURE"
	case storage.EventPortClosed:
		return "PORT CLOSED"
	case storage.EventServiceChanged:
		return "SERVICE CHANGED"
	case storage.EventServiceDisappeared:
		return "SERVICE DISAPPEARED"
	case storage.EventExpectedServiceMissing:
		return "EXPECTED SERVICE MISSING"
	default:
		return kind
	}
}

// PrintDiffHuman renders a diff report.
func PrintDiffHuman(w io.Writer, asset storage.Asset, confirmed, pending []storage.Event) {
	fmt.Fprintln(w, "PortPeek diff")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Asset: %s\n", asset.Label)
	fmt.Fprintf(w, "Target: %s\n\n", asset.Host)

	if len(confirmed) == 0 && len(pending) == 0 {
		fmt.Fprintln(w, "No confirmed drift.")
		return
	}

	for _, e := range confirmed {
		printEventBlock(w, e, "⚠ ")
	}
	for _, e := range pending {
		fmt.Fprintf(w, "• %s on port %d/%s observed but not yet confirmed (needs one more consistent scan).\n",
			humanKind(e.Kind), e.Port, e.Proto)
	}
}

// PrintAssetsHuman renders `portpeek list`.
func PrintAssetsHuman(w io.Writer, assets []storage.Asset) {
	if len(assets) == 0 {
		fmt.Fprintln(w, "No assets yet. Add one with: portpeek add <label> <host>")
		return
	}
	fmt.Fprintf(w, "%-20s %s\n", "LABEL", "TARGET")
	for _, a := range assets {
		fmt.Fprintf(w, "%-20s %s\n", a.Label, a.Host)
	}
}

// PrintHistoryHuman renders `portpeek history`.
func PrintHistoryHuman(w io.Writer, asset storage.Asset, scans []storage.Scan, obsByScan map[int64][]storage.Observation, port int) {
	fmt.Fprintf(w, "History for %s (%s)\n\n", asset.Label, asset.Host)
	if len(scans) == 0 {
		fmt.Fprintln(w, "No scan history recorded yet.")
		return
	}

	for _, sc := range scans {
		fmt.Fprintf(w, "%s  scan #%d  vantage=%s  ports=%s\n",
			sc.StartedAt.Format("2006-01-02 15:04:05 MST"), sc.ID, sc.Vantage, sc.PortsSpec)
		obs := obsByScan[sc.ID]
		sort.Slice(obs, func(i, j int) bool { return obs[i].Port < obs[j].Port })
		for _, o := range obs {
			if port != 0 && o.Port != port {
				continue
			}
			if port == 0 && o.State != "open" {
				continue
			}
			svc := deref(o.Service)
			if svc == "" {
				svc = "-"
			}
			fmt.Fprintf(w, "    %d/%s  %-8s %s\n", o.Port, o.Proto, o.State, svc)
		}
	}
}
