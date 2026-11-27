package catalog

import (
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
		stale, dynamic        bool
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
		},
		{
			name:      "dependency added since the lock",
			pyproject: project + "dependencies = [\"six\", \"idna\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			stale:     true,
		},
		{
			name:      "specifier changed since the lock",
			pyproject: project + "dependencies = [\"six>=1.17\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			stale:     true,
		},
		{
			name:      "dependency removed since the lock",
			pyproject: project + "dependencies = [\"six\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"idna\" }, { name = \"six\" }]\n"),
		},
		{
			name:      "group as locked, include-group left to the group it names",
			pyproject: project + "[dependency-groups]\ndev = [\"pytest >=7\", {include-group = \"lint\"}]\nlint = [\"ruff\"]\n",
			lock:      rootLock("[package.metadata]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\", specifier = \">=7\" }, { name = \"ruff\" }]\nlint = [{ name = \"ruff\" }]\n"),
		},
		{
			name:      "group entry added since the lock",
			pyproject: project + "[dependency-groups]\ndev = [\"pytest\", \"mypy\"]\n",
			lock:      rootLock("[package.metadata]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\" }]\n"),
			stale:     true,
		},
		{
			name:      "legacy dev-dependency added since the lock",
			pyproject: project + "[tool.uv]\ndev-dependencies = [\"mypy\", \"black\"]\n",
			lock:      rootLock("[package.metadata]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"mypy\" }]\n"),
			stale:     true,
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
			stale:     true,
		},
		{
			name:      "dependencies computed by the build backend",
			pyproject: project + "dynamic = [\"dependencies\"]\n",
			lock:      rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n"),
			dynamic:   true,
		},
		{
			name:      "project the lock does not hold",
			pyproject: project + "dependencies = [\"six\"]\n",
			lock:      "version = 1\n",
			stale:     true,
		},
		{
			name:      "lock that does not parse",
			pyproject: project + "dependencies = [\"six\"]\n",
			lock:      "[[[ not toml",
			stale:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "pyproject.toml", tt.pyproject)
			writeFile(t, dir, "uv.lock", tt.lock)
			_, stale, dynamic := checkUVLock(dir)
			if stale != tt.stale || dynamic != tt.dynamic {
				t.Errorf("stale, dynamic = %v, %v; want %v, %v", stale, dynamic, tt.stale, tt.dynamic)
			}
		})
	}
}
