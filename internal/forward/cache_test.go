package forward

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/scancache"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// A passive submission the cache deduplicated was not posted, so the verbose
// summary must not say it was. The collector's own line explains what happened.
func TestPassive_DeduplicatedPostIsNotReportedAsPosted(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "1")
	one := ossbom.New(ossbom.Environment{})
	one.AddComponent(ossbom.Component{Name: "lodash", Version: "4.17.21", Type: "npm"})

	// hit stands in for submit.Post finding a fresh posted entry.
	hit := func(ctx context.Context) {
		scancache.New(ctx, scancache.KeyInput{Kind: scancache.Posted}).Hit(2 * time.Minute)
	}

	cases := []struct {
		name string
		args []string
		bin  string
		wire func(t *testing.T)
	}{
		{
			name: "after the install (npm install)",
			bin:  "npm", args: []string{"install"},
			wire: func(t *testing.T) {
				swap(t, func(context.Context, string, []string) error { return nil },
					func(context.Context, check.Options) (*ossbom.SBOM, error) {
						t.Error("checkFn called on a bare install")
						return one, nil
					})
				swapScan(t, func(ctx context.Context, _ scanRequest) (*ossbom.SBOM, error) {
					hit(ctx)
					return one, nil
				})
			},
		},
		{
			name: "alongside the install (pip install pkg)",
			bin:  "pip", args: []string{"install", "requests==2.31.0"},
			wire: func(t *testing.T) {
				swap(t, func(context.Context, string, []string) error { return nil },
					func(ctx context.Context, _ check.Options) (*ossbom.SBOM, error) {
						hit(ctx)
						return one, nil
					})
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.wire(t)
			var buf bytes.Buffer
			old := errOut
			errOut = &buf
			t.Cleanup(func() { errOut = old })

			ctx := warn.NewContext(context.Background(), true)
			if err := Run(ctx, Options{Bin: c.bin, Args: c.args, Passive: true}); err != nil {
				t.Fatalf("Run: %v", err)
			}

			out := buf.String()
			if !strings.Contains(out, "identical scan already sent 2m ago; not sent again") {
				t.Errorf("the dedupe line was not printed:\n%s", out)
			}
			if strings.Contains(out, "scan posted") {
				t.Errorf("a deduplicated post was reported as posted:\n%s", out)
			}
		})
	}
}
