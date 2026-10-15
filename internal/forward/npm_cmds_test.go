package forward

import (
	"encoding/json"
	"maps"
	"os/exec"
	"slices"
	"testing"
)

// npm's command names are a table plus abbreviation, so they are held to the
// installed npm: the tables are diffed, and every prefix of every name is
// dereferenced by npm's own deref and by npmDeref. A name missing here is an
// install that forwards unchecked.
func TestNpmCmdListMatchesNpm(t *testing.T) {
	node, root := installedNpm(t)
	const script = `
const { commands, aliases, deref } = require(process.argv[1] + '/lib/utils/cmd-list.js')
const words = commands.concat(Object.keys(aliases))
const typed = new Set(['installTest', 'installCiTest', 'cleanInstall'])
for (const w of words) for (let i = 1; i <= w.length; i++) typed.add(w.slice(0, i))
const derefs = {}
for (const c of typed) derefs[c] = deref(c) || ''
console.log(JSON.stringify({ commands, aliases, derefs }))
`
	out, err := exec.Command(node, "-e", script, root).Output()
	if err != nil {
		t.Fatalf("read npm cmd-list: %v", err)
	}
	var npm struct {
		Commands []string
		Aliases  map[string]string
		Derefs   map[string]string
	}
	if err := json.Unmarshal(out, &npm); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(npm.Commands, npmCommands) {
		t.Errorf("npm commands = %q, npmCommands has %q (update npm_cmds.go)", npm.Commands, npmCommands)
	}
	if !maps.Equal(npm.Aliases, npmAliases) {
		t.Errorf("npm aliases = %v, npmAliases has %v (update npm_cmds.go)", npm.Aliases, npmAliases)
	}
	for typed, want := range npm.Derefs {
		if got := npmDeref(typed); got != want {
			t.Errorf("npmDeref(%q) = %q, npm runs %q", typed, got, want)
		}
	}
}

// Every name npm takes for an install is one, not just the four spelled out
// before (OSS: `npm isntall evil` forwarded unchecked).
func TestNpmInstallAliasesAreInstalls(t *testing.T) {
	for _, verb := range []string{
		"install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
		"isntal", "isntall", "ci", "clean-install", "ic", "install-clean", "isntall-clean",
		"update", "up", "upgrade", "udpate", "upd", "install-test", "it", "install-ci-test",
		"cit", "sit", "clean-install-test", "installTest",
	} {
		if _, ok := managers["npm"].installAt([]string{verb, "evil"}); !ok {
			t.Errorf("npm %s is not treated as an install", verb)
		}
	}
	for _, verb := range []string{"run", "test", "uninstall", "rm", "exec", "x", "ls", "install-", "foo"} {
		if _, ok := managers["npm"].installAt([]string{verb, "evil"}); ok {
			t.Errorf("npm %s is treated as an install", verb)
		}
	}
}
