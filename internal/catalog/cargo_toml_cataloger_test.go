package catalog

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

func TestCatalogCargoInheritsFromTheRootCargoFinds(t *testing.T) {
	// Each layout holds a serde pin Cargo never uses for the member, so reading the wrong root ships it.
	const member = "[package]\nname = \"m\"\n[dependencies]\nserde = { workspace = true }\n"
	pool := func(head, version string) string {
		return "[workspace]\n" + head + "[workspace.dependencies]\nserde = \"=" + version + "\"\n"
	}
	for _, tc := range []struct {
		name  string
		scan  string            // directory scanned, relative to the layout
		files map[string]string // {root} is replaced by the layout's path
		links map[string]string // symlink path to its target, both relative to the layout
		want  string            // serde's version, or "" when Cargo would find no readable root
	}{
		{
			name: "package.workspace names a root past a nearer one",
			files: map[string]string{
				"Cargo.toml":       pool("members = [\"a/b/m\"]\n", "1.0.100"),
				"a/Cargo.toml":     pool("", "1.0.200"),
				"a/b/m/Cargo.toml": "[package]\nname = \"m\"\nworkspace = \"../../..\"\n[dependencies]\nserde = { workspace = true }\n",
			},
			want: "1.0.100",
		},
		{
			name: "an absolute package.workspace is not joined to the member",
			files: map[string]string{
				"Cargo.toml":     pool("members = [\"a/m\"]\n", "1.0.100"),
				"a/Cargo.toml":   pool("", "1.0.200"),
				"a/m/Cargo.toml": "[package]\nname = \"m\"\nworkspace = '{root}'\n[dependencies]\nserde = { workspace = true }\n",
			},
			want: "1.0.100",
		},
		{
			name: "an ancestor package's workspace path is followed",
			files: map[string]string{
				"Cargo.toml":       pool("members = [\"x/a\", \"x/a/m\"]\n", "1.0.100"),
				"x/Cargo.toml":     pool("", "1.0.200"),
				"x/a/Cargo.toml":   "[package]\nname = \"a\"\nworkspace = \"../..\"\n",
				"x/a/m/Cargo.toml": member,
			},
			want: "1.0.100",
		},
		{
			name: "package.workspace naming a manifest without [workspace] finds no root",
			files: map[string]string{
				"Cargo.toml":     pool("", "1.0.200"),
				"lib/Cargo.toml": "[package]\nname = \"lib\"\n",
				"m/Cargo.toml":   "[package]\nname = \"m\"\nworkspace = \"../lib\"\n[dependencies]\nserde = { workspace = true }\n",
			},
		},
		{
			name: "package.workspace naming a root outside the scan is not read",
			scan: "scan",
			files: map[string]string{
				"Cargo.toml":        pool("", "1.0.200"),
				"scan/m/Cargo.toml": "[package]\nname = \"m\"\nworkspace = \"../..\"\n[dependencies]\nserde = { workspace = true }\n",
			},
		},
		{
			name: "a malformed ancestor stops the walk",
			files: map[string]string{
				"Cargo.toml":           pool("", "1.0.200"),
				"inner/Cargo.toml":     "[workspace\nmembers = [\"a/m\"]\n",
				"inner/a/m/Cargo.toml": member,
			},
		},
		{
			name: "an ancestor too large to read stops the walk",
			files: map[string]string{
				"Cargo.toml":         pool("", "1.0.200"),
				"inner/Cargo.toml":   pool("", "1.0.100") + strings.Repeat("#\n", maxManifestBytes/2),
				"inner/m/Cargo.toml": member,
			},
		},
		{
			name: "an ancestor linked out of the scan stops the walk",
			scan: "scan",
			files: map[string]string{
				"outside/Cargo.toml":      pool("", "1.0.100"),
				"scan/Cargo.toml":         pool("", "1.0.200"),
				"scan/inner/m/Cargo.toml": member,
			},
			links: map[string]string{"scan/inner/Cargo.toml": "outside/Cargo.toml"},
		},
		{
			name: "past a malformed ancestor, an outer root listing the member is its root",
			files: map[string]string{
				"Cargo.toml":           pool("members = [\"inner/a/m\"]\n", "1.0.200"),
				"inner/Cargo.toml":     "[workspace\nmembers = [\"a/m\"]\n",
				"inner/a/m/Cargo.toml": member,
			},
			want: "1.0.200",
		},
		{
			name: "past a malformed ancestor, a members glob lists the member",
			files: map[string]string{
				"Cargo.toml":           pool("members = [\"./inner/*/*\"]\n", "1.0.200"),
				"inner/Cargo.toml":     "[workspace\nmembers = [\"a/m\"]\n",
				"inner/a/m/Cargo.toml": member,
			},
			want: "1.0.200",
		},
		{
			name: "past a malformed ancestor, a glob of another depth does not list the member",
			files: map[string]string{
				"Cargo.toml":           pool("members = [\"inner/*\"]\n", "1.0.200"),
				"inner/Cargo.toml":     "[workspace\nmembers = [\"a/m\"]\n",
				"inner/a/m/Cargo.toml": member,
			},
		},
		{
			name: "past a malformed ancestor, an outer root excluding the member is not its root",
			files: map[string]string{
				"Cargo.toml":           pool("members = [\"inner/*/*\"]\nexclude = [\"inner/a\"]\n", "1.0.200"),
				"inner/Cargo.toml":     "[workspace\nmembers = [\"a/m\"]\n",
				"inner/a/m/Cargo.toml": member,
			},
		},
		{
			name: "past an ancestor linked out of the scan, an outer root listing the member is its root",
			scan: "scan",
			files: map[string]string{
				"outside/Cargo.toml":      pool("", "1.0.100"),
				"scan/Cargo.toml":         pool("members = [\"inner/m\"]\n", "1.0.200"),
				"scan/inner/m/Cargo.toml": member,
			},
			links: map[string]string{"scan/inner/Cargo.toml": "outside/Cargo.toml"},
			want:  "1.0.200",
		},
		{
			name: "past an empty ancestor, an outer root listing the member is its root",
			files: map[string]string{
				"Cargo.toml":           pool("members = [\"inner/a/m\"]\n", "1.0.200"),
				"inner/Cargo.toml":     "",
				"inner/a/m/Cargo.toml": member,
			},
			want: "1.0.200",
		},
		{
			name: "an ancestor with only comments stops the walk",
			files: map[string]string{
				"Cargo.toml":           pool("", "1.0.200"),
				"inner/Cargo.toml":     "# just a comment\n",
				"inner/a/m/Cargo.toml": member,
			},
		},
		{
			name: "an ancestor with only dependencies stops the walk",
			files: map[string]string{
				"Cargo.toml":           pool("", "1.0.200"),
				"inner/Cargo.toml":     "[dependencies]\nfoo = \"1\"\n",
				"inner/a/m/Cargo.toml": member,
			},
		},
		{
			name: "an ancestor [project] is a package",
			files: map[string]string{
				"Cargo.toml":           pool("", "1.0.200"),
				"inner/Cargo.toml":     "[project]\nname = \"inner\"\n",
				"inner/a/m/Cargo.toml": member,
			},
			want: "1.0.200",
		},
		{
			name: "a root that excludes the member is passed over",
			files: map[string]string{
				"Cargo.toml":      pool("members = [\"ws/m\"]\n", "1.0.100"),
				"ws/Cargo.toml":   pool("exclude = [\"m\"]\n", "1.0.200"),
				"ws/m/Cargo.toml": member,
			},
			want: "1.0.100",
		},
		{
			name: "an absolute exclude is not joined to the root",
			files: map[string]string{
				"Cargo.toml":      pool("members = [\"ws/m\"]\n", "1.0.100"),
				"ws/Cargo.toml":   pool("exclude = ['{root}/ws/m']\n", "1.0.200"),
				"ws/m/Cargo.toml": member,
			},
			want: "1.0.100",
		},
		{
			name: "a members entry overrides the same root's exclude",
			files: map[string]string{
				"Cargo.toml":      pool("", "1.0.200"),
				"ws/Cargo.toml":   pool("members = [\"m\"]\nexclude = [\"m\"]\n", "1.0.100"),
				"ws/m/Cargo.toml": member,
			},
			want: "1.0.100",
		},
		{
			name: "an exclude covers whole path components only",
			files: map[string]string{
				"Cargo.toml":       pool("", "1.0.200"),
				"ws/Cargo.toml":    pool("exclude = [\"m\"]\n", "1.0.100"),
				"ws/m2/Cargo.toml": member,
			},
			want: "1.0.100",
		},
		{
			name: "an exclude climbing out with .. covers nothing",
			files: map[string]string{
				"Cargo.toml":      pool("", "1.0.200"),
				"ws/Cargo.toml":   pool("exclude = [\"../ws/m\"]\n", "1.0.100"),
				"ws/m/Cargo.toml": member,
			},
			want: "1.0.100",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OSSPREY_RESOLVE_LATEST", "")
			var mu sync.Mutex
			var asked []string
			withResolveLatest(t, func(_ context.Context, _, name string) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				asked = append(asked, name)
				return "9.9.9", nil
			})

			dir := t.TempDir()
			for name, body := range tc.files {
				if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				writeFile(t, dir, name, strings.ReplaceAll(body, "{root}", dir))
			}
			for link, target := range tc.links {
				if err := os.Symlink(filepath.Join(dir, target), filepath.Join(dir, link)); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}

			ctx := warn.NewContext(context.Background(), true)
			got, err := Catalog(ctx, filepath.Join(dir, tc.scan), Options{NoExec: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			var serde []string
			for _, p := range got {
				if p.Name == "serde" {
					serde = append(serde, p.Version)
				}
			}
			warnings := warn.Drain(ctx)
			if tc.want == "" {
				if len(serde) != 0 || slices.Contains(asked, "serde") {
					t.Errorf("emitted serde %v (asked %v); Cargo finds no readable root, so the key is unvouched", serde, asked)
				}
				if !strings.Contains(warnings, `"serde" because its workspace root could not be read`) {
					t.Errorf("warnings = %q, want the dropped serde reported", warnings)
				}
				return
			}
			if !slices.Equal(serde, []string{tc.want}) {
				t.Errorf("serde = %v, want [%s] from the root Cargo finds", serde, tc.want)
			}
		})
	}
}

func TestCatalogCargoPinMustBeASemverRelease(t *testing.T) {
	// A pin Cargo's semver parser rejects names no crates.io release, so it resolves like a range.
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	withResolveLatest(t, func(context.Context, string, string) (string, error) { return "9.9.9", nil })
	for _, tc := range []struct{ spec, want string }{
		{"=1.0.0-", "9.9.9"},
		{"=1.0.0+", "9.9.9"},
		{"=01.0.0", "9.9.9"},
		{"=1.00.0", "9.9.9"},
		{"=1.0.0-alpha..1", "9.9.9"},
		{"=1.0.0-alpha.01", "9.9.9"},
		{"=1.0.0+sha..1", "9.9.9"},
		{"=1.0.0-alpha+b+c", "9.9.9"},
		// Cargo's parser refuses a core number past u64::MAX, but not a numeric pre-release identifier.
		{"=18446744073709551616.0.0", "9.9.9"},
		{"=1.99999999999999999999.0", "9.9.9"},
		{"=1.0.18446744073709551616", "9.9.9"},
		{"=18446744073709551615.0.0", "18446744073709551615.0.0"},
		{"=1.0.0-99999999999999999999", "1.0.0-99999999999999999999"},
		// Build metadata stays as written, since the release is fetched by its exact published string.
		{"=1.0.100+sha.5114f85", "1.0.100+sha.5114f85"},
		{"=1.0.0+001", "1.0.0+001"},
		{"=1.0.0-0a.1", "1.0.0-0a.1"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "Cargo.toml", "[package]\nname = \"app\"\n[dependencies]\nserde = \""+tc.spec+"\"\n")
			got, err := Catalog(context.Background(), dir, Options{NoExec: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			if len(got) != 1 || got[0].Name != "serde" || got[0].Version != tc.want {
				t.Errorf("Catalog() = %+v, want serde@%s", got, tc.want)
			}
		})
	}
}
