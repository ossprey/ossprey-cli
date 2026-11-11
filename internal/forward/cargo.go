package forward

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/registry"
)

// cargoResolveShorts are the short options of add, update, fetch and generate-lockfile that take a value (TestCargoFlagTablesMatchCargo).
var cargoResolveShorts = flagSet("-F", "-m", "-p", "-Z")

// cargoResolveAt matches the cargo verbs that resolve and lock but build nothing, unless asked for --help.
func cargoResolveAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "add", "update", "generate-lockfile", "fetch")(args)
	if !ok || cargoPrintsOnly(args, start, cargoResolveShorts) {
		return 0, false
	}
	return start, true
}

// cargoPrintsOnly reports whether cargo would print help or its version and run nothing: -h or --help after the verb, or either or -V/--version before it (verified with cargo 1.99.1).
func cargoPrintsOnly(args []string, start int, verbShorts map[string]bool) bool {
	globals := globalValueFlags["cargo"]
	return cargoOptionsHave(cargoSplitShorts(args[:start-1], globals), globals, "-h", "--help", "-V", "--version") ||
		cargoOptionsHave(cargoSplitShorts(args[start:], verbShorts), verbShorts, "-h", "--help")
}

// cargoOptionsHave reports whether one of flags is among split args' options before `--`.
func cargoOptionsHave(split []string, takes map[string]bool, flags ...string) bool {
	return len(cargoOptionsIn(split, takes, flags...)) > 0
}

// cargoOptionsIn are the options among split args before `--` that are one of flags, in order, never a value an option took (`-C-h` names a directory).
func cargoOptionsIn(split []string, takes map[string]bool, flags ...string) []string {
	var out []string
	for i := 0; i < len(split); i++ {
		switch a := split[i]; {
		case a == "--":
			return out
		case slices.Contains(flags, a):
			out = append(out, a)
		case takes[a] && i+1 < len(split) && !cargoOptionalSkips(a, split[i+1]):
			i++
		}
	}
	return out
}

// cargoShorts splits a group of short options as clap reads it: switches up to one in takes, which takes the rest less one leading `=`, else the next token (owes).
func cargoShorts(a string, takes map[string]bool) (split []string, owes bool) {
	if len(a) < 3 || a[0] != '-' || a[1] == '-' {
		return []string{a}, len(a) == 2 && takes[a]
	}
	for i := 1; i < len(a); {
		_, n := utf8.DecodeRuneInString(a[i:])
		short := "-" + a[i:i+n]
		if short == "--" {
			// cargo refuses the group; splitting it would forge an end of options.
			return []string{a}, false
		}
		i += n
		split = append(split, short)
		if takes[short] {
			if i == len(a) {
				return split, true
			}
			v := strings.TrimPrefix(a[i:], "=")
			if cargoOptionalSkips(short, v) {
				// clap reads `-p-h` as -p's value, so it stays one token, `-p=-h`, that no reader takes for an option.
				split[len(split)-1] = short + "=" + v
				return split, false
			}
			return append(split, v), false
		}
	}
	return split, false
}

// cargoSplitShorts writes each group of short options before any `--` one option per token, as cargoShorts reads it: `-qFpcre2` is `-q -F pcre2`.
func cargoSplitShorts(args []string, takes map[string]bool) []string {
	var out []string
	for i, a := range args {
		if a == "--" {
			return append(out, args[i:]...)
		}
		split, _ := cargoShorts(a, takes)
		out = append(out, split...)
	}
	return out
}

// cargoInstallAt matches `cargo install`, but not `cargo install --list` or a line that only prints help or the version.
func cargoInstallAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "install")(args)
	if !ok || cargoHas(args[start:], "--list") || cargoPrintsOnly(args, start, valueFlags["cargo"]) {
		return 0, false
	}
	return start, true
}

// cargoHas reports whether one of flags is among args before `--`.
func cargoHas(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if slices.Contains(flags, a) {
			return true
		}
	}
	return false
}

// cargoOptionalValues are install's options whose value is optional (TestCargoFlagTablesMatchCargo).
var cargoOptionalValues = flagSet("--bin", "--example", "--target")

// cargoResolveOptional are the cargoResolveShorts whose value is optional: add's -p, and update's, which `cargo update --help` hides (TestCargoFlagTablesMatchCargo).
var cargoResolveOptional = flagSet("-p")

// cargoOptionalSkips reports whether clap leaves next alone for flag: an optional value is never an option token, so `--bin -F pcre2` gives pcre2 to -F.
func cargoOptionalSkips(flag, next string) bool {
	return (cargoOptionalValues[flag] || cargoResolveOptional[flag]) && len(next) > 1 && next[0] == '-'
}

// cargoSourceFlags install every crate named from somewhere other than crates.io.
var cargoSourceFlags = flagSet("--git", "--path", "--index", "--registry")

// parseCargoInstall classifies `cargo install`'s arguments: each positional is a crate, --version pins them all, and a source flag other than crates.io, or else a defaultRegistry, takes them off crates.io; isCratesIo says whether a named registry is crates.io.
func parseCargoInstall(args []string, defaultRegistry string, isCratesIo func(registry string) bool) installArgs {
	args = cargoSplitShorts(args, valueFlags["cargo"])
	var crates []string
	version, source, cratesIo := "", "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "":
			continue
		case a == "--":
			crates = append(crates, args[i+1:]...)
			i = len(args)
			continue
		case !strings.HasPrefix(a, "-"):
			crates = append(crates, a)
			continue
		}
		flag, value, inline := splitFlagValue(a)
		if !inline && valueFlags["cargo"][flag] && i+1 < len(args) && !cargoOptionalSkips(flag, args[i+1]) {
			value = args[i+1]
			i++
		}
		switch {
		case flag == "--version" || flag == "--vers":
			version = value
		case flag == "--registry" && isCratesIo(value) || flag == "--index" && catalog.IsCratesIoIndex(value):
			source, cratesIo = "", true
		case cargoSourceFlags[flag]:
			source = flag + " " + value
		}
	}
	if source == "" && !cratesIo && defaultRegistry != "" {
		source = "registry.default " + defaultRegistry
	}
	var out installArgs
	for _, c := range crates {
		switch {
		case source != "":
			out.NonPackages = append(out.NonPackages, c)
		case version != "" && !strings.Contains(c, "@"):
			out.addCrate(c + "@" + version)
		default:
			out.addCrate(c)
		}
	}
	if source != "" {
		out.NonPackages = append(out.NonPackages, source)
	}
	return out
}

// addCrate adds one crate to install, never read as an archive, since a release such as 1.2.3-beta.zip is valid; a range, which check refuses, resolves to the latest release as a PyPI range does.
func (p *installArgs) addCrate(token string) {
	name, req, _ := strings.Cut(token, "@")
	s, err := check.ParseSpec("cargo", token)
	switch {
	case err == nil:
		p.addSpec(s, token)
	case req != "" && registry.IsCargoName(name):
		p.Specs = append(p.Specs, check.Spec{Ecosystem: "cargo", Name: name, Constraint: req})
	default:
		p.NonPackages = append(p.NonPackages, token)
	}
}

// cargoReleaseFn finds the releases cargo install may take for a crate; a var so tests need no network.
var cargoReleaseFn = registry.CargoInstallReleases

// cargoReleases pins each crate to the release cargo install takes from crates.io's index, failing when one cannot be found there.
func cargoReleases(ctx context.Context, specs []check.Spec) ([]check.Spec, error) {
	var out []check.Spec
	for _, s := range specs {
		req := s.Constraint
		if s.Version != "" {
			req = "=" + s.Version
		}
		vs, err := cargoReleaseFn(ctx, s.Name, req)
		if err != nil {
			return nil, fmt.Errorf("could not tell which release of %s cargo would install (%w), so it was not checked", s.Name, err)
		}
		for _, v := range vs {
			out = append(out, check.Spec{Ecosystem: "cargo", Name: s.Name, Version: v})
		}
	}
	return out, nil
}

// checkCargoFirst refuses a cargo command that only locks, since its Cargo.lock cannot be checked before it reaches the project yet.
func checkCargoFirst(ctx context.Context, m *Manager, opts Options) error {
	flushWarnings(ctx)
	cmd := cargoVerbOnly(m, opts.Args)
	return fmt.Errorf("did not run %s: ossprey does not check %s yet", cmd, cmd)
}

// cargoVerbOnly is the command and its verb in backticks, leaving out the rest of the line, where a --config value may hold a credential.
func cargoVerbOnly(m *Manager, args []string) string {
	return "`" + m.Bin + " " + args[verbIndex("cargo", args)] + "`"
}

// canonicalDir is dir with every link resolved, or as cleaned when it cannot be.
func canonicalDir(dir string) string {
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	return filepath.Clean(dir)
}

// cargoChdir is -C's directory joined to the working directory as chdir(2) is given it, else the working directory.
func cargoChdir(globals []string) string {
	dir, _ := os.Getwd()
	globals = cargoSplitShorts(globals, globalValueFlags["cargo"])
	for i := 0; i < len(globals); i++ {
		a := globals[i]
		var v string
		switch {
		case a == "-C" && i+1 < len(globals):
			v = globals[i+1]
			i++
		case globalValueFlags["cargo"][a]:
			i++
			continue
		default:
			continue
		}
		// Not cleaned yet: the kernel follows a link before the `..` after it, so `lnk/..` is the link target's parent (verified).
		next, ok := catalog.JoinIn(dir, v, filepath.VolumeName)
		if !ok {
			// cargo takes one -C, from this process's directory and environment, so Abs places a path relative to another drive as Windows does for cargo.
			next = v
			if abs, err := filepath.Abs(v); err == nil {
				next = abs
			}
		}
		dir = next
	}
	if runtime.GOOS == "windows" {
		// Windows takes `..` off the path as written, before it opens anything.
		return filepath.Clean(dir)
	}
	return dir
}

// cargoConfigDir is where cargo starts reading configuration: -C's directory, else the working directory, resolved as chdir(2) resolves it.
func cargoConfigDir(globals []string) string {
	// EvalSymlinks takes each `..` off the resolved prefix, as the kernel does.
	return canonicalDir(cargoChdir(globals))
}

// cargoDefaultRegistry is the registry other than crates.io that `cargo install` takes a crate from when the line names none, or "".
func cargoDefaultRegistry(args []string) string {
	v, _ := cargoInstallConfig(args, "CARGO_REGISTRY_DEFAULT", "registry", "default")
	if cargoRegistryIsCratesIo(args, v) {
		return ""
	}
	return v
}

// cargoRegistryIsCratesIo reports whether cargo install reads a named registry as crates.io: by its name, or by an index that is crates.io's.
func cargoRegistryIsCratesIo(args []string, name string) bool {
	if name == "crates-io" {
		return true
	}
	if name == "" || name == cargoUnreadConfig || name == cargoIncludedConfig {
		return false
	}
	// cargo spells a key as an environment variable in capitals, with '-' as '_'.
	env := "CARGO_REGISTRIES_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_INDEX"
	index, _ := cargoInstallConfig(args, env, "registries", name, "index")
	return catalog.IsCratesIoIndex(index)
}

// cargoTestIndexEnv is a test variable cargo 1.99.1 still honours, pointing crates.io at another index.
const cargoTestIndexEnv = "__CARGO_TEST_CRATES_IO_URL_DO_NOT_USE_THIS"

// cargoLocationKeys say where a [source] table's crates come from; set on crates.io's own table, any one replaces it as replace-with does (verified with cargo 1.99.1).
var cargoLocationKeys = []string{"registry", "local-registry", "directory", "git"}

// cargoReplacement says what cargo install takes crates.io's crates from instead of crates.io, or "" when nothing replaces it.
func cargoReplacement(args []string) string {
	const mayInstall = ", so cargo may install another source's copy, which was not checked"
	line, files := cargoInstallLevels(args)
	levels := slices.Concat(line, files)
	// cargo has no environment form for a [source] key (verified with cargo 1.99.1).
	for _, c := range levels {
		if c.err != nil {
			// One that is not a regular file counts too, since cargo reads it again and a FIFO may be written twice.
			return "a cargo config ossprey could not read may replace crates.io" + mayInstall
		}
		if with, ok := cargoValue(c.doc, "source", "crates-io", "replace-with").(string); ok {
			return fmt.Sprintf("crates.io is replaced by %q in your cargo config, so cargo installs that source's copy, which was not checked", with)
		}
		if c.doc["include"] != nil {
			return "a cargo config includes another file, which may replace crates.io" + mayInstall
		}
	}
	byName := cargoNamesCratesIo(args)
	for _, c := range levels {
		for _, k := range cargoLocationKeys {
			if cargoValue(c.doc, "source", "crates-io", k) != nil {
				// The value is left out, since a URL may hold a credential.
				return fmt.Sprintf("crates.io is replaced by the %s set for it in your cargo config, so cargo installs that copy, which was not checked", k)
			}
		}
		sources, _ := c.doc["source"].(map[string]any)
		for name, s := range sources {
			if !byName && name != "crates-io" && cargoValue(s, "replace-with") != nil {
				return "a cargo config replaces a source, which may be crates.io as this install names it" + mayInstall
			}
		}
	}
	if os.Getenv(cargoTestIndexEnv) != "" {
		return "crates.io is replaced by " + cargoTestIndexEnv + " in your environment, so cargo installs that source's copy, which was not checked"
	}
	return ""
}

// cargoNamesCratesIo reports whether cargo install reads crates.io by its own name, through no --index and no registry but crates-io, so only [source.crates-io] replaces it: cargo refuses a [source] naming crates.io's own index (verified with cargo 1.99.1).
func cargoNamesCratesIo(args []string) bool {
	split := cargoSplitShorts(args[verbIndex("cargo", args)+1:], valueFlags["cargo"])
	named := ""
	for i := 0; i < len(split) && split[i] != "--"; i++ {
		flag, value, inline := splitFlagValue(split[i])
		if !inline && valueFlags["cargo"][flag] && i+1 < len(split) && !cargoOptionalSkips(flag, split[i+1]) {
			value = split[i+1]
			i++
		}
		switch flag {
		case "--index":
			return false
		case "--registry":
			named = value
		}
	}
	if named == "" {
		named, _ = cargoInstallConfig(args, "CARGO_REGISTRY_DEFAULT", "registry", "default")
	}
	return named == "" || named == "crates-io"
}

// cargoUnknownDefault says why registry.default may be set where ossprey cannot read it, or "".
func cargoUnknownDefault(registry string) string {
	switch registry {
	case cargoUnreadConfig:
		return "a cargo config ossprey could not read may set the registry it installs from"
	case cargoIncludedConfig:
		return "a cargo config includes another file, which may set the registry it installs from"
	}
	return ""
}

// Stand-ins for a value a config may set that cannot be read, which no registry name or index URL can equal.
const (
	cargoUnreadConfig   = "a config it cannot read"
	cargoIncludedConfig = "an included config"
)

// cargoLevel is one config cargo install reads: its document, or why it could not be read or parsed.
type cargoLevel struct {
	doc map[string]any
	err error
}

// cargoInstallLevels are the configs cargo install reads, nearest first: the --config values from the last, then those from CARGO_HOME up, never the project's.
func cargoInstallLevels(args []string) (line, files []cargoLevel) {
	dir := cargoConfigDir(args[:max(verbIndex("cargo", args), 0)])
	for _, c := range slices.Backward(cargoConfigArgs(args)) {
		line = append(line, cargoLevelOf(cargoConfigArg(c, dir)))
	}
	home := catalog.CargoHome(dir)
	if home == "" {
		return line, nil
	}
	for _, f := range append(cargoConfigFiles(home), cargoConfigFile(home)) {
		if data, there, err := readConfig(f); there {
			files = append(files, cargoLevelOf(data, err))
		}
	}
	return line, files
}

// cargoLevelOf parses a config read with err, with the catalog's bounded parser.
func cargoLevelOf(data []byte, err error) cargoLevel {
	if err != nil {
		return cargoLevel{err: err}
	}
	doc, ok := cargoConfigDoc(data)
	if !ok {
		return cargoLevel{err: errCargoConfigRefused}
	}
	return cargoLevel{doc: doc}
}

// errCargoConfigRefused is a config the bounded parser refuses.
var errCargoConfigRefused = errors.New("refused by the bounded parser")

// value is the string c sets for key, or a stand-in when an include or a failed read may set it; one that is not a regular file sets nothing, since cargo install reads it again, when a pipe read once is empty.
func (c cargoLevel) value(key []string) (string, bool) {
	switch {
	case errors.Is(c.err, catalog.ErrNotRegular):
		return "", false
	case c.err != nil:
		return cargoUnreadConfig, true
	}
	if v, ok := cargoValue(c.doc, key...).(string); ok {
		return v, true
	}
	if c.doc["include"] != nil {
		return cargoIncludedConfig, true
	}
	return "", false
}

// cargoValue is what the tables from v down keys hold, or nil.
func cargoValue(v any, keys ...string) any {
	for _, k := range keys {
		t, _ := v.(map[string]any)
		v = t[k]
	}
	return v
}

// cargoInstallConfig is the value `cargo install` reads for a config key, also read from env, and whether one is set: the value set nearest the line wins.
func cargoInstallConfig(args []string, env string, key ...string) (string, bool) {
	line, files := cargoInstallLevels(args)
	for _, c := range line {
		if v, ok := c.value(key); ok {
			return v, true
		}
	}
	if v := os.Getenv(env); env != "" && v != "" {
		return v, true
	}
	for _, c := range files {
		if v, ok := c.value(key); ok {
			return v, true
		}
	}
	return "", false
}

// cargoConfigArgs are the --config values on the line, in order, before any `--`.
func cargoConfigArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		if args[i] == "--config" && i+1 < len(args) {
			out = append(out, args[i+1])
			i++
		} else if v, ok := strings.CutPrefix(args[i], "--config="); ok {
			out = append(out, v)
		}
	}
	return out
}

// cargoConfigArg is what cargo reads for a --config value: the file it names, from dir where cargo runs, when that exists, else the value as TOML.
func cargoConfigArg(c, dir string) ([]byte, error) {
	if c != "" {
		if data, there, err := readConfig(cargoConfigPath(c, dir)); there {
			return data, err
		}
	}
	return []byte(c), nil
}

// cargoConfigPath is the file a --config value names, read from dir where cargo runs.
func cargoConfigPath(c, dir string) string {
	if c != "" && dir != "" && filepath.VolumeName(c) == "" && !os.IsPathSeparator(c[0]) {
		// cargo joins the value to its working directory uncleaned, so the kernel applies `..` after any link.
		return dir + string(filepath.Separator) + c
	}
	return c
}

// cargoConfigFiles are the configs cargo reads from dir up, one per level.
func cargoConfigFiles(dir string) []string {
	var out []string
	for d := dir; ; d = filepath.Dir(d) {
		out = append(out, cargoConfigFile(filepath.Join(d, ".cargo")))
		if filepath.Dir(d) == d {
			return out
		}
	}
}

// cargoConfigFile is the one config cargo reads in dir: the legacy config when it opens, else config.toml.
func cargoConfigFile(dir string) string {
	legacy := filepath.Join(dir, "config")
	// cargo opens anything there, but a FIFO may never open, so only a regular file is opened here.
	if fi, err := os.Stat(legacy); err == nil && !fi.Mode().IsRegular() {
		return legacy
	}
	if f, err := os.Open(legacy); err == nil {
		f.Close()
		return legacy
	}
	return filepath.Join(dir, "config.toml")
}

// cargoConfigDoc parses a cargo config, or a --config KEY=VALUE, with the catalog's bounded parser; false is one it refuses or cannot decode.
func cargoConfigDoc(data []byte) (map[string]any, bool) {
	doc, err := catalog.ParseCargoConfig(data)
	return doc, err == nil
}

// readConfig reads the config at p when cargo would find one there, failing on one that is not a regular file, since a FIFO may never end.
func readConfig(p string) (data []byte, there bool, err error) {
	if !exists(p) {
		return nil, false, nil
	}
	data, _, err = catalog.ReadRegular(p, catalog.CargoManifestLimit)
	return data, true, err
}

// exists reports whether p names anything.
func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
