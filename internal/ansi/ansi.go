package ansi

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"
)

type Profile int

const (
	None Profile = iota
	Basic
	ANSI256
	TrueColor
)

func (p Profile) String() string {
	switch p {
	case None:
		return "None"
	case Basic:
		return "Basic"
	case ANSI256:
		return "ANSI256"
	case TrueColor:
		return "TrueColor"
	}
	return fmt.Sprintf("Profile(%d)", int(p))
}

var ciLogViewers = []string{"GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE"}

func Detect(w io.Writer) Profile {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return None
	}
	if v, ok := os.LookupEnv("FORCE_COLOR"); ok && v != "" {
		if v == "0" || strings.EqualFold(v, "false") {
			return None
		}
		return depthFromEnv()
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return depthFromEnv()
	}
	for _, k := range ciLogViewers {
		if os.Getenv(k) != "" {
			return Basic
		}
	}
	if isTerminal(w) {
		return depthFromEnv()
	}
	return None
}

func depthFromEnv() Profile {
	switch strings.ToLower(os.Getenv("COLORTERM")) {
	case "truecolor", "24bit":
		return TrueColor
	}
	if strings.Contains(os.Getenv("TERM"), "256color") {
		return ANSI256
	}
	return Basic
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(f.Fd()))
}

func (p Profile) wrap(code, s string) string {
	if p == None || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Profile) Bold(s string) string { return p.wrap("1", s) }

func (p Profile) Dim(s string) string { return p.wrap("2", s) }

func (p Profile) Red(s string) string {
	switch p {
	case ANSI256, TrueColor:
		return p.wrap("1;38;5;196", s)
	}
	return p.wrap("1;31", s)
}

func (p Profile) RGB(r, g, b int, s string) string {
	if p != TrueColor {
		return p.Red(s)
	}
	return p.wrap(fmt.Sprintf("1;38;2;%d;%d;%d", r, g, b), s)
}

var escapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func Strip(s string) string { return escapes.ReplaceAllString(s, "") }
