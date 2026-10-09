package scanner

import (
	"reflect"
	"testing"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{"single", "22", []int{22}, false},
		{"list", "22,80,443", []int{22, 80, 443}, false},
		{"range", "1-5", []int{1, 2, 3, 4, 5}, false},
		{"mixed", "22,80,1000-1002", []int{22, 80, 1000, 1001, 1002}, false},
		{"dedup", "22,22,22-22", []int{22}, false},
		{"whitespace", " 22 , 80 ", []int{22, 80}, false},
		{"unsorted input sorts output", "443,22,80", []int{22, 80, 443}, false},
		{"empty", "", nil, true},
		{"not a number", "abc", nil, true},
		{"zero", "0", nil, true},
		{"too large", "65536", nil, true},
		{"negative range", "100-50", nil, true},
		{"trailing comma", "22,80,", []int{22, 80}, false},
		{"malformed range", "22-", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePortSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePortSpec(%q): expected error, got none (result=%v)", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortSpec(%q): unexpected error: %v", tc.spec, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParsePortSpec(%q) = %v, want %v", tc.spec, got, tc.want)
			}
		})
	}
}

func TestParsePortSpecBoundaries(t *testing.T) {
	got, err := ParsePortSpec("1,65535")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{1, 65535}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFormatPortSpec(t *testing.T) {
	cases := []struct {
		name  string
		ports []int
		want  string
	}{
		{"empty", nil, ""},
		{"single", []int{22}, "22"},
		{"consecutive collapses to range", []int{1, 2, 3, 4}, "1-4"},
		{"non-consecutive stays a list", []int{22, 80, 443}, "22,80,443"},
		{"mixed", []int{22, 80, 81, 82, 443}, "22,80-82,443"},
		{"unsorted input", []int{443, 22}, "22,443"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatPortSpec(tc.ports)
			if got != tc.want {
				t.Fatalf("FormatPortSpec(%v) = %q, want %q", tc.ports, got, tc.want)
			}
		})
	}
}

func TestFormatPortSpecRoundTrip(t *testing.T) {
	ports, err := ParsePortSpec("22,80-82,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	spec := FormatPortSpec(ports)
	again, err := ParsePortSpec(spec)
	if err != nil {
		t.Fatalf("unexpected error reparsing %q: %v", spec, err)
	}
	if !reflect.DeepEqual(ports, again) {
		t.Fatalf("round trip mismatch: %v != %v", ports, again)
	}
}
