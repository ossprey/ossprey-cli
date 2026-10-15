package forward

import (
	"slices"
	"strings"
	"unicode"
)

// Copied from lib/utils/cmd-list.js in npm 10.9. npm accepts every alias and
// every unambiguous abbreviation of a command or alias, so `npm isntall x`,
// `npm upgrade x` and `npm insta x` all install. TestNpmCmdListMatchesNpm
// diffs these tables and npmDeref against the installed npm.
var npmCommands = []string{
	"access", "adduser", "audit", "bugs", "cache", "ci", "completion", "config",
	"dedupe", "deprecate", "diff", "dist-tag", "docs", "doctor", "edit", "exec",
	"explain", "explore", "find-dupes", "fund", "get", "help", "help-search", "hook",
	"init", "install", "install-ci-test", "install-test", "link", "ll", "login",
	"logout", "ls", "org", "outdated", "owner", "pack", "ping", "pkg", "prefix",
	"profile", "prune", "publish", "query", "rebuild", "repo", "restart", "root",
	"run-script", "sbom", "search", "set", "shrinkwrap", "star", "stars", "start",
	"stop", "team", "test", "token", "uninstall", "unpublish", "unstar", "update",
	"version", "view", "whoami",
}

var npmAliases = map[string]string{
	"author": "owner", "home": "docs", "issues": "bugs", "info": "view", "show": "view",
	"find": "search", "add": "install", "unlink": "uninstall", "remove": "uninstall",
	"rm": "uninstall", "r": "uninstall", "un": "uninstall", "rb": "rebuild", "list": "ls",
	"ln": "link", "create": "init", "i": "install", "it": "install-test",
	"cit": "install-ci-test", "up": "update", "c": "config", "s": "search", "se": "search",
	"tst": "test", "t": "test", "ddp": "dedupe", "v": "view", "run": "run-script",
	"clean-install": "ci", "clean-install-test": "install-ci-test", "x": "exec",
	"why": "explain", "la": "ll", "verison": "version", "ic": "ci", "innit": "init",
	"in": "install", "ins": "install", "inst": "install", "insta": "install",
	"instal": "install", "isnt": "install", "isnta": "install", "isntal": "install",
	"isntall": "install", "install-clean": "ci", "isntall-clean": "ci", "hlep": "help",
	"dist-tags": "dist-tag", "upgrade": "update", "udpate": "update", "rum": "run-script",
	"sit": "install-ci-test", "urn": "run-script", "ogr": "org", "add-user": "adduser",
}

// npmInstallCommands are the commands that install packages: named ones, or
// the project's manifest when none are named.
var npmInstallCommands = flagSet("install", "ci", "update", "install-test", "install-ci-test")

// npmDeref is cmd-list.js's deref: the command npm runs for what was typed, or
// "" for none.
func npmDeref(c string) string {
	if c == "" {
		return ""
	}
	// installTest is install-test.
	if strings.IndexFunc(c, unicode.IsUpper) >= 0 {
		var b strings.Builder
		for _, r := range c {
			if unicode.IsUpper(r) {
				b.WriteByte('-')
				r = unicode.ToLower(r)
			}
			b.WriteRune(r)
		}
		c = b.String()
	}
	if slices.Contains(npmCommands, c) {
		return c
	}
	if a, ok := npmAliases[c]; ok {
		return a
	}
	// abbrev: a word typed in full, or a prefix of exactly one word.
	match := ""
	for _, w := range npmWords() {
		if w == c {
			match = w
			break
		}
		if strings.HasPrefix(w, c) {
			if match != "" {
				return ""
			}
			match = w
		}
	}
	for npmAliases[match] != "" {
		match = npmAliases[match]
	}
	return match
}

func npmWords() []string {
	words := slices.Clone(npmCommands)
	for a := range npmAliases {
		words = append(words, a)
	}
	return words
}

// npmInstallAt matches an npm command that installs, under any name npm takes
// for it.
func npmInstallAt(args []string) (int, bool) {
	idx := verbIndex("npm", args)
	if idx >= 0 && npmInstallCommands[npmDeref(args[idx])] {
		return idx + 1, true
	}
	return 0, false
}
