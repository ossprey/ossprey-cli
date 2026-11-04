//go:build smoke

package smoke

// BenchmarkFallThrough measures what the forwarder costs a command it does not
// check. Every `npm run`, `pip list` or `git status` a developer, script or agent
// types goes through a shim when shims are installed, so the time between
// ossprey starting and the real manager starting is paid on every one of them.
//
// Each case runs the manager directly and then through `ossprey <manager>`,
// interleaved in the same loop so machine drift lands on both sides, and reports
// three numbers per op: direct-ms, ossprey-ms and overhead-ms (their difference).
// ns/op is zeroed because it would be the sum of both and means nothing here.
//
// The case list is built from forward.Managers(), so a new forwarder gets a
// `--version` case without touching this file; extraFallThrough adds a more
// realistic command per manager. A manager missing from PATH is skipped, not
// failed. Every case also asserts that it really fell through: the fake API must
// see no request and ossprey must exit as the manager did.
//
//	make bench-fallthrough            # BENCHTIME=20x make bench-fallthrough
//	go test -tags smoke -run '^$' -bench FallThrough -benchtime 10x ./test/smoke/
//	go test -tags smoke -run '^$' -bench 'FallThrough/npm/' -benchtime 20x ./test/smoke/

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

// extraFallThrough holds commands beyond `--version` that must pass straight
// through: offline, quick, and not an install by forward's reading. `noop` is a
// script in the fixture package.json, so `run noop` exercises the script path
// rather than just the manager's argv parse.
var extraFallThrough = map[string][][]string{
	"npm":    {{"run", "noop"}, {"config", "get", "registry"}},
	"pnpm":   {{"run", "noop"}},
	"yarn":   {{"run", "noop"}},
	"bun":    {{"run", "noop"}},
	"pip":    {{"list"}},
	"pip3":   {{"list"}},
	"uv":     {{"cache", "dir"}},
	"poetry": {{"about"}},
	"git":    {{"status", "--short"}},
}

type fallThroughCase struct {
	bin  string
	args []string
}

func (c fallThroughCase) name() string {
	return c.bin + "/" + strings.Join(c.args, "_")
}

func fallThroughCases() []fallThroughCase {
	bins := append(forward.Managers(), "git")
	var cases []fallThroughCase
	for _, bin := range bins {
		cases = append(cases, fallThroughCase{bin, []string{"--version"}})
		for _, args := range extraFallThrough[bin] {
			cases = append(cases, fallThroughCase{bin, args})
		}
	}
	return cases
}

func BenchmarkFallThrough(b *testing.B) {
	// Any request means a case was checked rather than passed through, which
	// would make its number a measurement of the fake API, not of the forwarder.
	var hits atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "a fall-through must not reach the API", http.StatusTeapot)
	}))
	defer api.Close()

	project := b.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"),
		[]byte(`{"name":"bench","version":"1.0.0","private":true,"scripts":{"noop":"node -e 0"}}`), 0o644); err != nil {
		b.Fatal(err)
	}
	if git, err := shim.LookPathReal("git"); err == nil {
		if out, err := exec.Command(git, "init", "-q", project).CombinedOutput(); err != nil {
			b.Fatalf("git init: %v\n%s", err, out)
		}
	}

	// One scratch home for the whole run, so the first case of each manager pays
	// any first-run setup during warm-up rather than in the loop.
	env := forwardEnv(b.TempDir(), api.URL, os.Getenv("PATH"))

	for _, c := range fallThroughCases() {
		b.Run(c.name(), func(b *testing.B) {
			// LookPathReal, not exec.LookPath: on a machine with shims installed
			// the PATH `npm` is ossprey, and "direct" would measure it twice.
			real, err := shim.LookPathReal(c.bin)
			if err != nil {
				b.Skipf("%s not on PATH", c.bin)
			}
			direct := func() int { return benchRun(b, project, env, real, c.args...) }
			viaOssprey := func() int {
				return benchRun(b, project, env, binPath, append([]string{c.bin}, c.args...)...)
			}

			// Warm up both sides (page cache, first-run state) and confirm the
			// forwarder really is a pass-through for this command.
			before := hits.Load()
			want, got := direct(), viaOssprey()
			if got != want {
				b.Fatalf("ossprey %s %v exited %d, %s directly exited %d", c.bin, c.args, got, c.bin, want)
			}

			var directDur, osspreyDur time.Duration
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t0 := time.Now()
				direct()
				t1 := time.Now()
				viaOssprey()
				osspreyDur += time.Since(t1)
				directDur += t1.Sub(t0)
			}
			b.StopTimer()

			if n := hits.Load() - before; n != 0 {
				b.Fatalf("ossprey %s %v made %d API request(s): it was checked, not passed through", c.bin, c.args, n)
			}
			ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) / float64(b.N) }
			b.ReportMetric(0, "ns/op")
			b.ReportMetric(ms(directDur), "direct-ms/op")
			b.ReportMetric(ms(osspreyDur), "ossprey-ms/op")
			b.ReportMetric(ms(osspreyDur-directDur), "overhead-ms/op")
		})
	}
}

// benchRun runs one invocation and returns its exit code. Output is discarded:
// only the time to completion and the exit code matter here.
func benchRun(b *testing.B, dir string, env []string, bin string, args ...string) int {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	err := cmd.Run()
	if ctx.Err() != nil {
		b.Fatalf("%s %v did not finish within %s", bin, args, subprocessTimeout)
	}
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			b.Fatalf("run %s %v: %v", bin, args, err)
		}
		return ee.ExitCode()
	}
	return 0
}
