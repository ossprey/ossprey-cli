package main

import (
	"context"
	"errors"
	"testing"

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
