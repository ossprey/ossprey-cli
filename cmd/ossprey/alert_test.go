package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ansi"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/severity"
)

func TestReportMalwarePrintsBannerThenPlainLines(t *testing.T) {
	for _, k := range []string{"FORCE_COLOR", "CLICOLOR_FORCE", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE"} {
		t.Setenv(k, "")
	}
	var buf bytes.Buffer
	old := verdictOut
	verdictOut = &buf
	t.Cleanup(func() { verdictOut = old })

	sbom := ossbom.New(ossbom.Environment{})
	sbom.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:pypi/requests@2.31.0", "bad"))
	sbom.AddVulnerability(ossbom.NewMalwareVulnerability("V2", "pkg:npm/left-pad@1.3.0", "bad"))

	if !reportMalware(sbom, severity.FailingFloor) {
		t.Fatal("reportMalware must report malware")
	}
	out := buf.String()
	banner := strings.Index(out, "Ossprey found 2 malicious packages. Scan failed.")
	plain := strings.Index(out, "Error: WARNING: requests:2.31.0 contains malware. Remediate this immediately")
	if banner < 0 || plain < 0 {
		t.Fatalf("missing banner or plain line:\n%s", out)
	}
	if banner > plain {
		t.Errorf("banner must precede the plain lines:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("a non-terminal writer must get no escape codes:\n%q", out)
	}
}

func TestReportMalwareErrorLinesAreRedWhenColoured(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("COLORTERM", "")
	t.Setenv("TERM", "xterm")
	var buf bytes.Buffer
	old := verdictOut
	verdictOut = &buf
	t.Cleanup(func() { verdictOut = old })

	sbom := ossbom.New(ossbom.Environment{})
	sbom.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:pypi/requests@2.31.0", "bad"))
	reportMalware(sbom, severity.FailingFloor)

	want := ansi.Basic.Red("Error: WARNING: requests:2.31.0 contains malware. Remediate this immediately")
	if !strings.Contains(buf.String(), want) {
		t.Errorf("error line should be red:\n%q", buf.String())
	}
}

func TestReportMalwareInformationalHasNoBanner(t *testing.T) {
	var buf bytes.Buffer
	old := verdictOut
	verdictOut = &buf
	t.Cleanup(func() { verdictOut = old })

	sbom := ossbom.New(ossbom.Environment{})
	v := ossbom.NewMalwareVulnerability("V1", "pkg:pypi/requests@2.31.0", "note")
	v.Severity = "Info"
	sbom.AddVulnerability(v)

	if reportMalware(sbom, severity.FailingFloor) {
		t.Fatal("informational finding must not fail")
	}
	out := buf.String()
	if strings.Contains(out, "Ossprey found") || strings.Contains(out, "███") {
		t.Errorf("informational finding must not draw the banner:\n%s", out)
	}
	if !strings.HasPrefix(out, "Note: ") {
		t.Errorf("expected a Note: line, got:\n%s", out)
	}
}
