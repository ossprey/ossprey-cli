package forward

// Generated from npm's own option definitions
// (@npmcli/config/lib/definitions) for npm 10.9 and 12.1, plus the extras
// npx's bin/npx-cli.js adds. TestNpxTablesAgreeWithInstalledNpm re-derives them
// from whatever npm is on PATH, so a new npm that changes a flag's meaning fails
// a test rather than silently moving the package check onto the wrong token.
//
// Why two tables and not one: npx parses its arguments twice — its own pre-pass,
// then npm's nopt — and nopt reads an *unknown* flag as a boolean. So a flag's
// meaning depends on which npm is installed: `npx --allow-scripts x y` runs y
// on npm 12 (a string option) and x on npm 10 (unknown, so boolean). A flag in
// neither table is ambiguous, and npxParse checks both readings.

// npxSwitches take no value in any known npm.
var npxSwitches = setOf(
	"all", "allow-same-version", "allow-scripts-pending", "allow-scripts-pin",
	"allow-unused-patches", "always-spawn", "audit", "bin-links", "browser",
	"bypass-2fa", "color", "commit-hooks", "dangerously-allow-all-scripts",
	"description", "dev", "diff-ignore-all-space", "diff-name-only",
	"diff-no-prefix", "diff-text", "dry-run", "engine-strict", "expect-results",
	"force", "foreground-scripts", "format-package-lock", "fund",
	"git-tag-version", "global", "global-style", "h", "help", "if-present",
	"ignore-existing", "ignore-extension", "ignore-patch-failures",
	"ignore-scripts", "include-attestations", "include-staged",
	"include-workspace-root", "init-private", "install-links", "json",
	"keep-edit-dir", "legacy-bundling", "legacy-peer-deps", "link", "long",
	"no-install", "offline", "omit-lockfile-registry-resolved", "optional",
	"package-lock", "package-lock-only", "packages-all", "parseable",
	"prefer-dedupe", "prefer-offline", "prefer-online", "production",
	"progress", "provenance", "q", "quiet", "read-only", "rebuild-bundle",
	"save", "save-bundle", "save-dev", "save-exact", "save-optional",
	"save-peer", "save-prod", "shell-auto-fallback", "shrinkwrap",
	"sign-git-commit", "sign-git-tag", "strict-allow-scripts", "strict-npmrc",
	"strict-peer-deps", "strict-ssl", "timing", "unicode", "update-notifier",
	"usage", "v", "version", "versions", "workspaces", "workspaces-update",
	"yes")

// npxOptions take a value in every known npm.
var npxOptions = setOf(
	"_auth", "access", "also", "audit-level", "auth-type", "before", "c", "ca",
	"cache", "cache-max", "cache-min", "cafile", "call", "cert", "cidr", "cpu",
	"depth", "diff", "diff-dst-prefix", "diff-src-prefix", "diff-unified",
	"editor", "expect-result-count", "fetch-retries", "fetch-retry-factor",
	"fetch-retry-maxtimeout", "fetch-retry-mintimeout", "fetch-timeout", "git",
	"globalconfig", "heading", "https-proxy", "include", "init-author-email",
	"init-author-name", "init-author-url", "init-license", "init-module",
	"init-version", "init.author.email", "init.author.name", "init.author.url",
	"init.license", "init.module", "init.version", "install-strategy", "key",
	"libc", "local-address", "location", "lockfile-version", "loglevel",
	"logs-dir", "logs-max", "maxsockets", "message", "n", "node-arg",
	"node-options", "noproxy", "npm", "omit", "only", "os", "otp", "p",
	"pack-destination", "package", "prefix", "preid", "provenance-file",
	"proxy", "registry", "replace-registry-host", "save-prefix", "sbom-format",
	"sbom-type", "scope", "script-shell", "searchexclude", "searchlimit",
	"searchopts", "searchstaleness", "shell", "tag", "tag-version-prefix",
	"umask", "user-agent", "userconfig", "viewer", "which", "workspace")

// npxShorthands expands a short or aliased flag to the long option it means.
// npx rewrites -p and --shell itself; the rest are npm's. An empty value is a
// shorthand that carries its own value (`-s` is `--loglevel silent`), so it
// consumes nothing. -n is absent on purpose: npx reads it as the removed
// --node-arg, which takes a value, before npm's `--no-yes` meaning applies.
var npxShorthands = map[string]string{
	"?":         "usage",
	"B":         "save-bundle",
	"C":         "prefix",
	"D":         "save-dev",
	"E":         "save-exact",
	"H":         "usage",
	"L":         "location",
	"O":         "save-optional",
	"P":         "save-prod",
	"S":         "save",
	"a":         "all",
	"c":         "call",
	"d":         "", // --loglevel info
	"dd":        "", // --loglevel verbose
	"ddd":       "", // --loglevel silly
	"desc":      "description",
	"enjoy-by":  "before",
	"f":         "force",
	"g":         "global",
	"h":         "usage",
	"help":      "usage",
	"iwr":       "include-workspace-root",
	"l":         "long",
	"local":     "no-global",
	"m":         "message",
	"no":        "no-yes",
	"p":         "package",
	"porcelain": "parseable",
	"q":         "", // --loglevel warn
	"quiet":     "", // --loglevel warn
	"readonly":  "read-only",
	"reg":       "registry",
	"s":         "", // --loglevel silent
	"shell":     "script-shell",
	"silent":    "", // --loglevel silent
	"v":         "version",
	"verbose":   "", // --loglevel verbose
	"w":         "workspace",
	"ws":        "workspaces",
	"y":         "yes",
}

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
