package catalog

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestPinnedRequirements(t *testing.T) {
	cases := []struct {
		name string
		body string
		want map[string]string
	}{{
		name: "four-segment and zero-padded releases survive intact",
		body: "ossprey-internal==0.1.138.0\npadded==0.01.138.0\n",
		want: map[string]string{"ossprey-internal": "0.1.138.0", "padded": "0.01.138.0"},
	}, {
		// The OSS-1869 shapes: syft's [0-9a-zA-Z.*] constraint class stops at
		// the separator, reporting a shorter version that names a different
		// release (or none).
		name: "pre-release, post-release, dev and local segments survive",
		body: "a==1.0.0-beta.1\nb==1.2.3+local1\nc==2.0.0.post1\nd==3.0.0.dev20240101+g1a2b3c\ne==4.0.0rc1\nf==5.0.0_1\n",
		want: map[string]string{
			"a": "1.0.0-beta.1",
			"b": "1.2.3+local1",
			"c": "2.0.0.post1",
			"d": "3.0.0.dev20240101+g1a2b3c",
			"e": "4.0.0rc1",
			"f": "5.0.0_1",
		},
	}, {
		// syft strips only "==", so "===1.0" reaches the SBOM as "=1.0".
		name: "arbitrary equality keeps the version, drops the operator",
		body: "a===0.1.138.0\n",
		want: map[string]string{"a": "0.1.138.0"},
	}, {
		name: "extras, spacing, markers, comments and hashes are stripped",
		body: "a[dev,test] == 1.0.0-beta.1  # pin me\n" +
			"b==2.0.0-rc.1 ; python_version >= \"3.8\"\n" +
			"c==3.0.0-rc.1 --hash=sha256:abc --hash=sha256:def\n",
		want: map[string]string{"a": "1.0.0-beta.1", "b": "2.0.0-rc.1", "c": "3.0.0-rc.1"},
	}, {
		name: "line continuations are joined before parsing",
		body: "a==1.0.0-beta.1 \\\n    --hash=sha256:abc\nb \\\n  == \\\n  2.0.0-beta.1\n",
		want: map[string]string{"a": "1.0.0-beta.1", "b": "2.0.0-beta.1"},
	}, {
		// Anything that does not name exactly one release is syft's to guess;
		// a wrong pin here would override a correct guess.
		name: "ranges, wildcards and multi-constraints are not pins",
		body: "a>=1.0\nb~=1.2\nc==1.2.*\nd==1.0,!=1.1\ne>=1.0,<2.0\nf\n",
		want: map[string]string{},
	}, {
		name: "option lines and editable installs are not requirements",
		body: "-r base.txt\n--index-url https://example.invalid/simple\n-e ./libs/mine\n--hash=sha256:abc\n",
		want: map[string]string{},
	}, {
		name: "url requirements name no version",
		body: "a @ https://example.invalid/a.whl\nb @ git+https://example.invalid/b#egg=b\n",
		want: map[string]string{},
	}, {
		// pip only starts a comment at line start or after whitespace, so a
		// "#egg=" fragment is part of the requirement, not a comment.
		name: "blank lines, full-line comments and CRLF endings",
		body: "\r\n# a comment\r\na==1.0.0-beta.1\r\n\r\n",
		want: map[string]string{"a": "1.0.0-beta.1"},
	}, {
		name: "names are matched PEP 503 canonically",
		body: "My_Pkg.Name==1.0.0-beta.1\n",
		want: map[string]string{"my-pkg-name": "1.0.0-beta.1"},
	}, {
		name: "the last pin for a name wins, as pip resolves it",
		body: "a==1.0.0-beta.1\na==2.0.0-beta.1\n",
		want: map[string]string{"a": "2.0.0-beta.1"},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pinnedRequirements([]byte(tc.body))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("pinnedRequirements() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCatalog_RequirementsVersionsCarryThrough is the OSS-1869 end-to-end: a
// requirements.txt whose pins carry PEP 440 separators syft's constraint regex
// truncates. Every version must reach the catalog exactly as written, or the
// purl names a release the project never installs.
func TestCatalog_RequirementsVersionsCarryThrough(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", strings.Join([]string{
		"ossprey-internal==0.1.138.0",
		"prerelease==1.0.0-beta.1",
		"localver==1.2.3+local1",
		"arbitrary===2.0.0.post1",
		"plain==8.1.7",
	}, "\n")+"\n")

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	versions := map[string]string{}
	for _, p := range got {
		versions[p.Name] = p.Version
	}
	want := map[string]string{
		"ossprey-internal": "0.1.138.0",
		"prerelease":       "1.0.0-beta.1",
		"localver":         "1.2.3+local1",
		"arbitrary":        "2.0.0.post1",
		"plain":            "8.1.7",
	}
	for name, wantV := range want {
		if versions[name] != wantV {
			t.Errorf("%s: version = %q, want %q", name, versions[name], wantV)
		}
	}
}

// TestCatalog_UnparseableLineKeepsOtherPackages pins the partial-results
// contract: syft's generic cataloger returns what it did parse alongside an
// "unknown" error for what it could not. Discarding its packages on that error
// emptied the SBOM of every Python package over a single bad line — a scan
// that silently checked nothing.
func TestCatalog_UnparseableLineKeepsOtherPackages(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "click==8.1.7\n@@@ not a requirement @@@\nflask>2.0\n")

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	var found bool
	for _, p := range got {
		if p.Name == "click" && p.Version == "8.1.7" && p.Type == "pypi" {
			found = true
		}
	}
	if !found {
		t.Errorf("click@8.1.7 dropped because a sibling line was unparseable; got %+v", got)
	}
}
