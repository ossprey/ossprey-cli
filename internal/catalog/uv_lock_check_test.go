package catalog

import (
	"slices"
	"testing"
)

// rootLock is a uv.lock whose project at "." was made from meta, its [package.metadata] tables.
func rootLock(meta string) string {
	return "version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" + meta
}

func TestCheckUVLock(t *testing.T) {
	const project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n"
	tests := []struct {
		name, pyproject, lock string
		project, dynamic      bool
		groups                []string
		floor                 string
	}{
		{
			name: "uv's own spelling of each requirement",
			pyproject: project + `dependencies = [
  "six",
  "Flask_Login >= 0.6 ; python_version >= '3.9'",
  "idna<4, >=2",
  "Requests[socks] ~= 2.31",
  "attrs (>=22.1)",
  "click @ https://files.example/click-8.1.7-py3-none-any.whl",
]
`,
			// As uv 0.10.4 wrote it for the pyproject above.
			lock: rootLock(`[package.metadata]
requires-dist = [
    { name = "attrs", specifier = ">=22.1" },
    { name = "click", url = "https://files.example/click-8.1.7-py3-none-any.whl" },
    { name = "flask-login", marker = "python_full_version >= '3.9'", specifier = ">=0.6" },
    { name = "idna", specifier = ">=2,<4" },
    { name = "requests", extras = ["socks"], specifier = "~=2.31" },
    { name = "six" },
]
`),
			floor: "3.9",
		},
		{
			name:      "dependency added since the lock",
			pyproject: project + "dependencies = [\"six\", \"idna\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			project:   true,
			floor:     "3.9",
		},
		{
			name:      "specifier changed since the lock",
			pyproject: project + "dependencies = [\"six>=1.17\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			project:   true,
			floor:     "3.9",
		},
		{
			name:      "dependency removed since the lock",
			pyproject: project + "dependencies = [\"six\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"idna\" }, { name = \"six\" }]\n"),
			floor:     "3.9",
		},
		{
			name:      "group as locked, include-group left to the group it names",
			pyproject: project + "[dependency-groups]\ndev = [\"pytest >=7\", {include-group = \"lint\"}]\nlint = [\"ruff\"]\n",
			lock:      rootLock("[package.metadata]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\", specifier = \">=7\" }, { name = \"ruff\" }]\nlint = [{ name = \"ruff\" }]\n"),
			floor:     "3.9",
		},
		{
			name:      "group entry added since the lock",
			pyproject: project + "[dependency-groups]\ndev = [\"pytest\", \"mypy\"]\n",
			lock:      rootLock("[package.metadata]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\" }]\n"),
			groups:    []string{"dev"},
			floor:     "3.9",
		},
		{
			name:      "legacy dev-dependency added since the lock",
			pyproject: project + "[tool.uv]\ndev-dependencies = [\"mypy\", \"black\"]\n",
			lock:      rootLock("[package.metadata]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"mypy\" }]\n"),
			groups:    []string{"dev"},
			floor:     "3.9",
		},
		{
			name:      "virtual workspace root as locked",
			pyproject: "[tool.uv.workspace]\nmembers = [\"pkgs/*\"]\n\n[dependency-groups]\ndev = [\"pytest\"]\n",
			lock:      "version = 1\n\n[manifest]\nmembers = [\"a\"]\n\n[manifest.dependency-groups]\ndev = [{ name = \"pytest\" }]\n",
		},
		{
			name:      "virtual workspace root with a group entry added",
			pyproject: "[tool.uv.workspace]\nmembers = [\"pkgs/*\"]\n\n[dependency-groups]\ndev = [\"pytest\", \"evil\"]\n",
			lock:      "version = 1\n\n[manifest]\nmembers = [\"a\"]\n\n[manifest.dependency-groups]\ndev = [{ name = \"pytest\" }]\n",
			groups:    []string{"dev"},
		},
		{
			name:      "dependencies computed by the build backend",
			pyproject: project + "dynamic = [\"dependencies\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			dynamic:   true,
			floor:     "3.9",
		},
		{
			name:      "project the lock does not hold",
			pyproject: project + "dependencies = [\"six\"]\n",
			lock:      "version = 1\n",
			project:   true,
		},
		{
			name:      "lock that does not parse",
			pyproject: project + "dependencies = [\"six\"]\n",
			lock:      "[[[ not toml",
			project:   true,
		},
		{
			name:      "registry requirement now a direct URL",
			pyproject: project + "dependencies = [\"click @ https://files.example/click-9.0-py3-none-any.whl\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"click\" }]\n"),
			project:   true,
			floor:     "3.9",
		},
		{
			name:      "direct URL changed since the lock",
			pyproject: project + "dependencies = [\"click @ https://files.example/click-9.0-py3-none-any.whl\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"click\", url = \"https://files.example/click-8.1.7-py3-none-any.whl\" }]\n"),
			project:   true,
			floor:     "3.9",
		},
		{
			name:      "direct URL now a registry requirement",
			pyproject: project + "dependencies = [\"click\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"click\", url = \"https://files.example/click-8.1.7-py3-none-any.whl\" }]\n"),
			project:   true,
			floor:     "3.9",
		},
		{
			name:      "git, path and tool.uv.sources entries as locked",
			pyproject: project + "dependencies = [\"six @ git+https://github.com/benjaminp/six@1.17.0\", \"locallib\", \"wheel @ file:///wheels/wheel-0.45.1-py3-none-any.whl\"]\n\n[tool.uv.sources]\nlocallib = { path = \"locallib\" }\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [\n    { name = \"locallib\", directory = \"locallib\" },\n    { name = \"six\", git = \"https://github.com/benjaminp/six?rev=1.17.0\" },\n    { name = \"wheel\", path = \"/wheels/wheel-0.45.1-py3-none-any.whl\" },\n]\n"),
			floor:     "3.9",
		},
		{
			name:      "registry requirement now from tool.uv.sources",
			pyproject: project + "dependencies = [\"locallib\"]\n\n[tool.uv.sources]\nlocallib = { path = \"locallib\" }\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"locallib\" }]\n"),
			project:   true,
			floor:     "3.9",
		},
		{
			name:      "groups in conflict, both added since the lock",
			pyproject: project + "requires-python = \">=3.11\"\ndependencies = [\"six\"]\n[dependency-groups]\nb = [\"six==1.17.0\"]\na = [\"six==1.16.0\"]\n\n[tool.uv]\nconflicts = [[{ group = \"a\" }, { group = \"b\" }]]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			groups:    []string{"a", "b"},
			floor:     "3.11",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "pyproject.toml", tt.pyproject)
			writeFile(t, dir, "uv.lock", tt.lock)
			d := checkUVLock(dir)
			if d.project != tt.project || d.dynamic != tt.dynamic || !slices.Equal(d.groups, tt.groups) || d.floor != tt.floor {
				t.Errorf("drift = project %v, dynamic %v, groups %v, floor %q; want %v, %v, %v, %q", d.project, d.dynamic, d.groups, d.floor, tt.project, tt.dynamic, tt.groups, tt.floor)
			}
		})
	}
}
