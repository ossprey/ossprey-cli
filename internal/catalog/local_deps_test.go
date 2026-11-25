package catalog

import "testing"

func TestHasLocalDeps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"empty dir", nil, false},
		{"registry deps only", map[string]string{"package.json": `{"dependencies":{"x":"^1.0.0","y":"npm:z@2","g":"github:o/r"},"devDependencies":{"t":"latest"}}`}, false},
		{"file: dependency", map[string]string{"package.json": `{"dependencies":{"local":"file:./local"}}`}, true},
		{"link: dev dependency", map[string]string{"package.json": `{"devDependencies":{"local":"link:../local"}}`}, true},
		{"portal: optional dependency", map[string]string{"package.json": `{"optionalDependencies":{"local":"portal:./local"}}`}, true},
		{"bare relative path", map[string]string{"package.json": `{"dependencies":{"local":"./packages/local"}}`}, true},
		{"workspace: protocol", map[string]string{"package.json": `{"dependencies":{"local":"workspace:*"}}`}, true},
		{"nested override", map[string]string{"package.json": `{"overrides":{"a":{"b":"file:./patched-b"}}}`}, true},
		{"yarn resolution", map[string]string{"package.json": `{"resolutions":{"a/b":"file:./patched-b"}}`}, true},
		{"pnpm override", map[string]string{"package.json": `{"pnpm":{"overrides":{"b":"link:./patched-b"}}}`}, true},
		{"bun catalog", map[string]string{"package.json": `{"dependencies":{"local":"catalog:"},"catalog":{"local":"file:./local"}}`}, true},
		{"bun named catalog", map[string]string{"package.json": `{"dependencies":{"local":"catalog:dev"},"catalogs":{"dev":{"local":"link:./local"}}}`}, true},
		{"registry catalog", map[string]string{"package.json": `{"dependencies":{"x":"catalog:"},"catalog":{"x":"^1.0.0"}}`}, false},
		{"pnpm yaml override", map[string]string{"pnpm-workspace.yaml": "overrides:\n  b: file:./patched-b\n"}, true},
		{"pnpm yaml catalog", map[string]string{"pnpm-workspace.yaml": "catalog:\n  local: link:./local\n"}, true},
		{"pnpm yaml named catalog", map[string]string{"pnpm-workspace.yaml": "catalogs:\n  dev:\n    local: file:./local\n"}, true},
		{"pnpm yaml registry settings", map[string]string{"pnpm-workspace.yaml": "catalog:\n  x: 1.0.0\noverrides:\n  y: ^2\nonlyBuiltDependencies:\n  - esbuild\n"}, false},
		{"unparseable pnpm yaml", map[string]string{"pnpm-workspace.yaml": "overrides: [\n"}, true},
		{"local git repository", map[string]string{"package.json": `{"dependencies":{"local":"git+file:./vendor/x"}}`}, true},
		{"remote git repository", map[string]string{"package.json": `{"dependencies":{"x":"git+https://github.com/o/x.git","y":"git+ssh://git@github.com/o/y.git"}}`}, false},
		// A script or a field that is not a dependency spec is not one.
		{"path outside the dependency fields", map[string]string{"package.json": `{"main":"./index.js","scripts":{"x":"file:./a"},"files":["./dist"]}`}, false},
		{"unparseable package.json", map[string]string{"package.json": `{`}, true},

		{"plain pyproject", map[string]string{"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"requests>=2\", \"httpx[cli] ; python_version > '3.8'\"]\n"}, false},
		{"PEP 508 file reference", map[string]string{"pyproject.toml": "[project]\ndependencies = [\"local @ file:///abs/local\"]\n"}, true},
		{"relative direct reference", map[string]string{"pyproject.toml": "[project.optional-dependencies]\ndev = [\"local @ ./libs/local\"]\n"}, true},
		{"remote direct reference", map[string]string{"pyproject.toml": "[project]\ndependencies = [\"x @ https://example.com/x-1.0.tar.gz\", \"y @ git+https://github.com/o/y\"]\n"}, false},
		{"dependency group", map[string]string{"pyproject.toml": "[dependency-groups]\ndev = [\"local @ file:./libs/local\", {include-group = \"test\"}]\ntest = [\"pytest\"]\n"}, true},
		{"uv path source", map[string]string{"pyproject.toml": "[project]\ndependencies = [\"local\"]\n\n[tool.uv.sources]\nlocal = { path = \"./libs/local\" }\n"}, true},
		{"uv workspace source", map[string]string{"pyproject.toml": "[tool.uv.sources]\nlocal = { workspace = true }\n"}, true},
		{"uv multiple sources", map[string]string{"pyproject.toml": "[tool.uv.sources]\nlocal = [{ index = \"a\", marker = \"sys_platform == 'linux'\" }, { path = \"./libs/local\" }]\n"}, true},
		{"uv remote sources", map[string]string{"pyproject.toml": "[tool.uv.sources]\nx = { git = \"https://github.com/o/x\" }\ny = { index = \"internal\" }\n"}, false},
		// PyPI has packages named `path` and `workspace`: a name is not a key.
		{"uv source for a package named path", map[string]string{"pyproject.toml": "[tool.uv.sources]\npath = { index = \"internal\" }\n"}, false},
		{"poetry path dependency", map[string]string{"pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.11\"\nlocal = { path = \"../local\", develop = true }\n"}, true},
		{"poetry group path dependency", map[string]string{"pyproject.toml": "[tool.poetry.group.dev.dependencies]\nlocal = { path = \"./libs/local\" }\n"}, true},
		{"poetry registry dependencies", map[string]string{"pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.11\"\npath = \"^16.0\"\nrequests = { version = \"^2\", extras = [\"socks\"] }\n\n[tool.poetry.group.dev.dependencies]\npytest = \"^8\"\n"}, false},
		{"setuptools dynamic dependencies", map[string]string{"pyproject.toml": "[project]\ndynamic = [\"dependencies\"]\n\n[tool.setuptools.dynamic]\ndependencies = { file = [\"reqs/base.txt\"] }\n"}, true},
		{"hatch context reference", map[string]string{"pyproject.toml": "[project]\ndependencies = [\"local @ {root:uri}/libs/local\"]\n"}, true},
		{"local git reference", map[string]string{"pyproject.toml": "[project]\ndependencies = [\"local @ git+file:///abs/local\"]\n"}, true},
		{"hatch dynamic dependencies", map[string]string{"pyproject.toml": "[project]\ndynamic = [\"dependencies\"]\n\n[tool.hatch.metadata.hooks.requirements_txt]\nfiles = [\"deps/base.txt\"]\n"}, true},
		{"dynamic optional dependencies", map[string]string{"pyproject.toml": "[project]\ndynamic = [\"version\", \"optional-dependencies\"]\n"}, true},
		{"dynamic version only", map[string]string{"pyproject.toml": "[project]\ndynamic = [\"version\", \"readme\"]\n"}, false},
		{"setuptools dynamic version only", map[string]string{"pyproject.toml": "[tool.setuptools.dynamic]\nversion = { attr = \"a.__version__\" }\n"}, false},
		{"unparseable pyproject", map[string]string{"pyproject.toml": "[project\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tc.files {
				writeFixture(t, dir, rel, content)
			}
			if got := HasLocalDeps(dir); got != tc.want {
				t.Errorf("HasLocalDeps = %v, want %v", got, tc.want)
			}
		})
	}
}
