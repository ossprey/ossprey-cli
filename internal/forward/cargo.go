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

// parseCargoInstall classifies `cargo install`'s arguments: each positional is a crate, --version pins them all, and a source flag other than crates.io, or else a defaultRegistry, takes them off crates.io.
func parseCargoInstall(args []string, defaultRegistry string) installArgs {
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
		case flag == "--registry" && value == "crates-io" || flag == "--index" && catalog.IsCratesIoIndex(value):
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

// addCrate adds one crate to install; a range, which check refuses, resolves to the latest release as a PyPI range does.
func (p *installArgs) addCrate(token string) {
	name, req, _ := strings.Cut(token, "@")
	if _, err := check.ParseSpec("cargo", token); err != nil && req != "" && registry.IsCargoName(name) {
		p.Specs = append(p.Specs, check.Spec{Ecosystem: "cargo", Name: name, Constraint: req})
		return
	}
	p.addTarget("cargo", token)
}

// checkCargoFirst refuses a cargo command that only locks, since its Cargo.lock cannot be checked before it reaches the project yet.
func checkCargoFirst(ctx context.Context, m *Manager, opts Options) error {
	flushWarnings(ctx)
	verb := opts.Args[verbIndex("cargo", opts.Args)]
	return fmt.Errorf("did not run `%s %s`: ossprey does not check `cargo %s` yet", m.Bin, strings.Join(opts.Args, " "), verb)
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
		if !filepath.IsAbs(v) {
			// Not cleaned yet: the kernel follows a link before the `..` after it, so `lnk/..` is the link target's parent (verified).
			v = dir + string(filepath.Separator) + v
		}
		dir = v
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
	// The value set nearest the line wins; an include, or a regular file that cannot be read or that the bounded parser refuses, may set it too.
	pick := func(data []byte, err error) (string, bool) {
		if errors.Is(err, catalog.ErrNotRegular) {
			// cargo install reads its config again from CARGO_HOME, when a pipe read once is empty, so one that is not a regular file sets nothing.
			return "", false
		}
		doc, ok := cargoConfigDoc(data)
		if err != nil || !ok {
			return "a config it cannot read", true
		}
		if reg, _ := doc["registry"].(map[string]any); reg != nil {
			if v, ok := reg["default"].(string); ok {
				return v, true
			}
		}
		if doc["include"] != nil {
			return "an included config", true
		}
		return "", false
	}
	found := func(v string) string {
		if v == "crates-io" {
			return ""
		}
		return v
	}
	dir := cargoConfigDir(args[:max(verbIndex("cargo", args), 0)])
	for _, c := range slices.Backward(cargoConfigArgs(args)) {
		if v, ok := pick(cargoConfigArg(c, dir)); ok {
			return found(v)
		}
	}
	if v := os.Getenv("CARGO_REGISTRY_DEFAULT"); v != "" {
		return found(v)
	}
	home := catalog.CargoHome(dir)
	if home == "" {
		return ""
	}
	// cargo install reads no project config, only those from CARGO_HOME up.
	for _, f := range append(cargoConfigFiles(home), cargoConfigFile(home)) {
		if data, there, err := readConfig(f); there {
			if v, ok := pick(data, err); ok {
				return found(v)
			}
		}
	}
	return ""
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
