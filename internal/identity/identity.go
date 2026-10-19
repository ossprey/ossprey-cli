// Package identity says who ran a command and which coding-agent session it
// ran in, so passive submissions can be grouped by person and by session.
package identity

import (
	"os"
	"os/user"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// AgentClaudeCode is the Agent value for a command run by Claude Code.
const AgentClaudeCode = "claude-code"

// PersonResolver names the person behind a submission. A better resolver (a
// login, a directory lookup) can replace the default without touching callers.
type PersonResolver interface {
	// Person returns a stable name for the person, or "" when unknown.
	Person(machine string) string
}

// OSUserHost names a person as `user@machine`, from the OS account.
type OSUserHost struct {
	// Username returns the OS account name; nil means the current user.
	Username func() string
}

// Person implements PersonResolver.
func (r OSUserHost) Person(machine string) string {
	name := currentUsername
	if r.Username != nil {
		name = r.Username
	}
	u := name()
	if u == "" {
		return ""
	}
	if machine == "" {
		return u
	}
	return u + "@" + machine
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		// Windows reports DOMAIN\user; the domain adds nothing next to the host.
		return u.Username[strings.LastIndex(u.Username, `\`)+1:]
	}
	for _, k := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// Session is the coding-agent session a command ran in.
type Session struct {
	Agent string
	// ID is "" when the agent exports none, as a local Claude Code does:
	// such sessions are told apart only by machine.
	ID string
}

// sessionIDVars are read in order. Claude Code exports a session id only in
// cloud sessions; a local CLI exports none.
var sessionIDVars = []string{"CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_REMOTE_SESSION_ID"}

// DetectSession reads the agent session from the environment.
func DetectSession(getenv func(string) string) Session {
	// CLAUDECODE is set in every subprocess Claude Code spawns, CHILD_SESSION
	// by newer versions only; either marks a command it ran.
	if getenv("CLAUDECODE") != "1" && getenv("CLAUDE_CODE_CHILD_SESSION") != "1" {
		return Session{}
	}
	s := Session{Agent: AgentClaudeCode}
	for _, k := range sessionIDVars {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			s.ID = v
			break
		}
	}
	return s
}

// Default resolves people for Stamp.
var Default PersonResolver = OSUserHost{}

// Stamp fills Person, Agent and AgentSession. Call it after MachineName is
// final, since the person is named relative to it.
func Stamp(e *ossbom.Environment) {
	if e.Person == "" {
		e.Person = Default.Person(e.MachineName)
	}
	s := DetectSession(os.Getenv)
	e.Agent = s.Agent
	e.AgentSession = s.ID
}
