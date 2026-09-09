package alert

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ossprey/ossprey-cli/internal/ansi"
)

const Width = 72

const (
	indent      = "    "
	inner       = Width - 2
	nameCol     = 26
	versionCol  = 12
	maxRows     = 8
	shownOnOver = 6
	dashboard   = "https://dashboard.ossprey.com"
)

type Finding struct {
	Name      string
	Version   string
	Ecosystem string
}

var letters = []string{
	"███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗",
	"████╗ ████║██╔══██╗██║     ██║    ██║██╔══██╗██╔══██╗██╔════╝",
	"██╔████╔██║███████║██║     ██║ █╗ ██║███████║██████╔╝█████╗  ",
	"██║╚██╔╝██║██╔══██║██║     ██║███╗██║██╔══██║██╔══██╗██╔══╝  ",
	"██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗",
	"╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
}

var gradient = [][3]int{
	{230, 30, 30},
	{235, 55, 28},
	{240, 80, 25},
	{245, 100, 20},
	{250, 120, 12},
	{255, 140, 0},
}

func Malware(findings []Finding, outcome string, p ansi.Profile) string {
	if len(findings) == 0 {
		return ""
	}
	var b strings.Builder
	edge := func(s string) { b.WriteString(p.Red(s) + "\n") }
	row := func(plain, styled string) {
		pad := strings.Repeat(" ", inner-utf8.RuneCountInString(plain))
		b.WriteString(p.Red("│") + styled + pad + p.Red("│") + "\n")
	}
	blank := func() { row("", "") }
	text := func(s string) { row(indent+s, indent+s) }
	styledText := func(s string, style func(string) string) { row(indent+s, indent+style(s)) }

	edge("┌" + strings.Repeat("─", inner) + "┐")
	blank()
	for i, l := range letters {
		c := gradient[i]
		row(indent+l, indent+p.RGB(c[0], c[1], c[2], l))
	}
	blank()
	styledText(headline(len(findings), outcome), p.Bold)
	blank()
	styledText(pad("PACKAGE", nameCol)+" "+pad("VERSION", versionCol)+" ECOSYSTEM", p.Dim)
	styledText(strings.Repeat("─", inner-len(indent)-3), p.Dim)
	shown := findings
	if len(findings) > maxRows {
		shown = findings[:shownOnOver]
	}
	for _, f := range shown {
		styledText(pad(f.Name, nameCol)+" "+pad(f.Version, versionCol)+" "+f.Ecosystem, p.Bold)
	}
	if n := len(findings) - len(shown); n > 0 {
		styledText(fmt.Sprintf("and %d more, listed below", n), p.Dim)
	}
	blank()
	styledText("ADVISORY", p.Dim)
	for _, l := range advisory(len(findings)) {
		text(l)
	}
	blank()
	text("Details: " + dashboard)
	blank()
	edge("└" + strings.Repeat("─", inner) + "┘")
	return b.String()
}

func headline(n int, outcome string) string {
	if n == 1 {
		return "Ossprey found 1 malicious package. " + outcome
	}
	return fmt.Sprintf("Ossprey found %d malicious packages. %s", n, outcome)
}

func advisory(n int) []string {
	subject := "These packages are"
	object := "them"
	if n == 1 {
		subject = "This package is"
		object = "it"
	}
	return wrap(fmt.Sprintf("%s known to contain malware. Do not install, import or run %s. Remove %s from your dependencies, rotate any credentials on a machine where %s may already have run, and re-run the scan.",
		subject, object, object, object), inner-2*len(indent))
}

func wrap(s string, width int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		switch {
		case line == "":
			line = w
		case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(w) > width:
			out = append(out, line)
			line = w
		default:
			line += " " + w
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func pad(s string, width int) string {
	if n := utf8.RuneCountInString(s); n > width {
		r := []rune(s)
		return string(r[:width-1]) + "…"
	} else if n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}
