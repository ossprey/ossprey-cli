package catalog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

func TestCatalogerEntryFromToolErrorNamesTheCauseButHidesTheOutput(t *testing.T) {
	err := newToolError("uv", "/repo", "warning: experimental\nerror: The build backend returned an error\n  Caused by: boom")
	e := catalogerEntry("uv", err)

	if want := "uv: could not resolve /repo (the build backend returned an error)"; e.One != want {
		t.Errorf("One = %q, want %q", e.One, want)
	}
	if want := "uv: could not resolve %d manifests"; e.Many != want {
		t.Errorf("Many = %q, want %q", e.Many, want)
	}
	if e.DetailLabel != "uv" {
		t.Errorf("DetailLabel = %q, want %q", e.DetailLabel, "uv")
	}
	if len(e.Detail) != 3 {
		t.Errorf("Detail = %d lines, want the full output kept for verbose", len(e.Detail))
	}
	// The class keys on the cataloger, so uv and npm never share a count.
	if !strings.Contains(e.Class, "uv") {
		t.Errorf("Class = %q, want it keyed by cataloger", e.Class)
	}
}

func TestCatalogerEntryFromAPlainErrorCarriesNoDetail(t *testing.T) {
	e := catalogerEntry("pyproject", errors.New("parse pyproject.toml: unexpected token"))

	if want := "pyproject: parse pyproject.toml: unexpected token"; e.One != want {
		t.Errorf("One = %q, want %q", e.One, want)
	}
	if len(e.Detail) != 0 {
		t.Errorf("Detail = %v, want none for a non-subprocess error", e.Detail)
	}
}

// Syft's own catalogers return what they parsed alongside an error naming the
// lines they could not. That error was discarded outright, so a malformed
// requirement produced silence and simply went missing from the SBOM.
func TestParseEntryCollapsesAMultiLineSyftError(t *testing.T) {
	err := errors.New("unknown error(s):\n  requirements.txt:12: unparseable\n  requirements.txt:19: unparseable")
	e := parseEntry("python-cataloger", err)

	if strings.Contains(e.One, "\n") {
		t.Errorf("One = %q, want a single line", e.One)
	}
	if !strings.Contains(e.One, "could not be parsed") {
		t.Errorf("One = %q, want it to say what happened", e.One)
	}
	if len(e.Detail) != 3 {
		t.Errorf("Detail = %d lines, want the full error kept for verbose", len(e.Detail))
	}
}

// Past the scan deadline every remaining lookup fails on the expired context,
// not on the registry. Reporting those as "registry unreachable" would blame an
// outage for our own timeout — and scan.Run already reports the deadline once.
func TestResolveVersionlessIsSilentPastTheDeadline(t *testing.T) {
	old := resolveLatestFn
	resolveLatestFn = func(ctx context.Context, _, _ string) (string, error) {
		return "", ctx.Err()
	}
	t.Cleanup(func() { resolveLatestFn = old })

	ctx, cancel := context.WithCancel(warn.NewContext(context.Background(), false))
	cancel()

	pkgs := []Package{{Type: "npm", Name: "left-pad"}, {Type: "npm", Name: "is-odd"}}
	resolveVersionless(ctx, pkgs, Options{})

	if got := warn.Drain(ctx); got != "" {
		t.Errorf("Drain() = %q, want nothing past the deadline", got)
	}
}

// A live context still reports, or the guard above would silence everything.
func TestResolveVersionlessStillWarnsBeforeTheDeadline(t *testing.T) {
	old := resolveLatestFn
	resolveLatestFn = func(context.Context, string, string) (string, error) {
		return "", errors.New("dial tcp: connection refused")
	}
	t.Cleanup(func() { resolveLatestFn = old })

	ctx := warn.NewContext(context.Background(), false)
	resolveVersionless(ctx, []Package{{Type: "npm", Name: "left-pad"}}, Options{})

	if got := warn.Drain(ctx); !strings.Contains(got, "registry unreachable") {
		t.Errorf("Drain() = %q, want the unreachable-registry warning", got)
	}
}

// OSS-1869, end to end: syft's generic cataloger returns everything it parsed
// alongside an error naming the lines it could not. Dropping the packages on
// err != nil once emptied an SBOM of every Python package over a single
// unparseable line — a scan that silently checked nothing. The packages must
// survive, and the error must now be reported rather than discarded.
func TestCatalogKeepsWhatItParsedAndWarnsAboutTheRest(t *testing.T) {
	root := t.TempDir()
	reqs := "flask==2.0.1\nthis is not a requirement at all !!!\nrequests==2.31.0\n"
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := warn.NewContext(context.Background(), false)
	pkgs, err := Catalog(ctx, root, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}

	var got []string
	for _, p := range pkgs {
		got = append(got, p.Name+"=="+p.Version)
	}
	for _, want := range []string{"flask==2.0.1", "requests==2.31.0"} {
		if !slices.Contains(got, want) {
			t.Errorf("Catalog() = %v, want it to keep %q despite the unparseable line", got, want)
		}
	}

	// The other half: that error used to be read as `pkgs, _, _` and dropped,
	// so the line went missing with nothing said about it.
	drained := warn.Drain(ctx)
	if !strings.Contains(drained, "could not be parsed") {
		t.Errorf("warnings = %q, want the unparseable line reported", drained)
	}
	for _, line := range strings.Split(strings.TrimRight(drained, "\n"), "\n") {
		if len([]rune(line)) > 200 {
			t.Errorf("a %d-rune warning line is the problem this ticket was about:\n%s", len([]rune(line)), line)
		}
	}
}
