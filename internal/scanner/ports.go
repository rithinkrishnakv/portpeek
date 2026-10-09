package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePortSpec parses a port specification like "22,80,443" or "1-1000" or
// a mix such as "22,80,1000-1024" into a deduplicated, sorted slice of
// ports. An empty spec is an error; callers that want the default port set
// should check for an empty string before calling this.
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	seen := make(map[int]struct{})
	var out []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			lo, err := parsePort(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			hi, err := parsePort(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			if lo > hi {
				return nil, fmt.Errorf("invalid port range %q: start greater than end", part)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					out = append(out, p)
				}
			}
			continue
		}

		p, err := parsePort(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no ports parsed from specification %q", spec)
	}

	sort.Ints(out)
	return out, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("out of range 1-65535: %d", p)
	}
	return p, nil
}

// FormatPortSpec renders a sorted port slice back into a compact spec
// string, collapsing consecutive runs into ranges. Used for recording what
// was actually requested on a scan row.
func FormatPortSpec(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)

	var parts []string
	start := sorted[0]
	prev := sorted[0]
	flush := func(end int) {
		if start == end {
			parts = append(parts, strconv.Itoa(start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, end))
		}
	}
	for _, p := range sorted[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		flush(prev)
		start = p
		prev = p
	}
	flush(prev)
	return strings.Join(parts, ",")
}
