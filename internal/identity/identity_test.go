package identity

import (
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

func envOf(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestOSUserHostNamesThePersonOnTheMachine(t *testing.T) {
	r := OSUserHost{Username: func() string { return "david" }}
	cases := map[string]string{"vm": "david@vm", "": "david"}
	for machine, want := range cases {
		if got := r.Person(machine); got != want {
			t.Errorf("Person(%q) = %q, want %q", machine, got, want)
		}
	}
}

func TestOSUserHostWithNoUserIsUnknown(t *testing.T) {
	r := OSUserHost{Username: func() string { return "" }}
	if got := r.Person("vm"); got != "" {
		t.Errorf("Person = %q, want empty", got)
	}
}

func TestDetectSession(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want Session
	}{
		{"not under claude code", map[string]string{"CLAUDE_CODE_SESSION_ID": "s1"}, Session{}},
		{"local claude code exports no id", map[string]string{"CLAUDECODE": "1"}, Session{Agent: AgentClaudeCode}},
		{"cloud session id", map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s1"}, Session{AgentClaudeCode, "s1"}},
		{"remote id when no session id", map[string]string{"CLAUDE_CODE_CHILD_SESSION": "1", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_1"}, Session{AgentClaudeCode, "cse_1"}},
		{"session id wins over remote id", map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s1", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_1"}, Session{AgentClaudeCode, "s1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectSession(envOf(c.vars)); got != c.want {
				t.Errorf("DetectSession = %+v, want %+v", got, c.want)
			}
		})
	}
}

type fixedPerson string

func (p fixedPerson) Person(string) string { return string(p) }

func TestStampUsesTheResolverAndKeepsAGivenPerson(t *testing.T) {
	prev := Default
	t.Cleanup(func() { Default = prev })
	Default = fixedPerson("someone")
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "s1")

	e := ossbom.Environment{MachineName: "vm"}
	Stamp(&e)
	if e.Person != "someone" || e.Agent != AgentClaudeCode || e.AgentSession != "s1" {
		t.Errorf("Stamp = %+v", e)
	}

	given := ossbom.Environment{Person: "kept"}
	Stamp(&given)
	if given.Person != "kept" {
		t.Errorf("Stamp replaced a given person: %q", given.Person)
	}
}
