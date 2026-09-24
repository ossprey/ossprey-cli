package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/update"
)

func TestRootChecksForUpdateAfterSuccessfulCommand(t *testing.T) {
	old := updateNoticeFn
	t.Cleanup(func() { updateNoticeFn = old })

	calls := 0
	updateNoticeFn = func(_ context.Context, opts update.NoticeOptions) error {
		calls++
		if opts.Current != version {
			t.Errorf("current version = %q, want %q", opts.Current, version)
		}
		return errors.New("update service unavailable")
	}

	root := newRootCmd()
	root.SetArgs([]string{"scan", "--skip-ci"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if calls != 1 {
		t.Errorf("update checks = %d, want 1", calls)
	}
}

func TestNoMalwareLine(t *testing.T) {
	mixed := ossbom.New(ossbom.Environment{})
	mixed.AddComponent(ossbom.Component{Name: "left-pad", Version: "1.3.0", Type: "npm"})
	mixed.AddComponent(ossbom.Component{Name: "serde", Version: "1.0.200", Type: "cargo"})
	mixed.AddComponent(ossbom.Component{Name: "rand", Version: "0.8.5", Type: "cargo"})
	mixed.Findings = []ossbom.Finding{
		{Purl: "pkg:cargo/serde@1.0.200", Type: "UNSUPPORTED"},
		{Purl: "pkg:cargo/rand@0.8.5", Type: "UNSUPPORTED"},
	}

	full := ossbom.New(ossbom.Environment{})
	full.AddComponent(ossbom.Component{Name: "left-pad", Version: "1.3.0", Type: "npm"})

	tests := []struct {
		name string
		sbom *ossbom.SBOM
		want string
	}{
		{"everything scanned", full, "No malware found"},
		{"two of three unscanned", mixed, "No malware found in 1 of 3 packages"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := noMalwareLine(tt.sbom); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
