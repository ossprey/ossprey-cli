package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/severity"
)

// The verdicts a Report can carry. They are part of the file's contract with
// whatever reads it — CI glue of any flavour — so treat them as API.
//
// The report is where the CLI's responsibility to CI ends: it states what was
// found. Turning that into a Markdown table, a pull-request comment, a job
// summary or an annotation belongs to the consumer, not here. Resist adding
// rendering or vendor-specific output to this package however convenient it
// would be for one caller: `ossprey/gh-action` is only the first consumer, and
// a CLI carrying features that exist solely for GitHub Actions is worse for
// everyone else who has to install it.
const (
	VerdictClean   = "clean"
	VerdictMalware = "malware"
	VerdictSkipped = "skipped"
	// VerdictInformational is a scan whose only findings are below the failing
	// severity floor. Its own verdict for the same reason "skipped" is: the scan
	// did find something and said so, and a consumer that renders it as "no
	// malware found" is hiding a finding we deliberately surfaced. Consumers
	// that only know clean/malware/skipped should treat it as non-failing.
	VerdictInformational = "informational"
)

// Finding is one malicious package, pre-split so a consumer doesn't have to
// parse PURLs to render "name @ version".
type Finding struct {
	Purl      string `json:"purl"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	ID        string `json:"id,omitempty"`
	Type      string `json:"type,omitempty"`
	// Severity grades the finding (Info, Low, Medium, High, Critical). Empty
	// when the API could not grade it, which counts as failing. Only Info is
	// below the failing floor.
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// Skip explains a quota-exhausted scan (verdict "skipped").
type Skip struct {
	Message string `json:"message"`
	ResetAt string `json:"reset_at,omitempty"`
}

// Report is the machine-readable verdict written by `--report`. It exists
// because the human output on stdout is not parseable and the full OSSBOM
// (`-o`) is both large and shaped for the platform rather than for CI glue —
// and because stdout itself is spoken for: `--local` puts the OSSBOM there,
// so nothing else may.
//
// Findings is always non-nil so `jq '.findings | length'` works on a clean
// scan too, and it holds only findings that fail: a consumer counting it to
// say "N malicious packages" stays correct without knowing what a severity is.
// Findings below the failing floor go in Informational instead, which is
// omitted when empty so a consumer that predates it sees no change.
type Report struct {
	Verdict       string    `json:"verdict"`
	Project       string    `json:"project,omitempty"`
	Path          string    `json:"path,omitempty"`
	Components    int       `json:"components"`
	Findings      []Finding `json:"findings"`
	Informational []Finding `json:"informational,omitempty"`
	Skipped       *Skip     `json:"skipped,omitempty"`
}

// NewReport summarises a scanned SBOM: "malware" when any finding is at or
// above the failing severity floor, "informational" when it found only findings
// below it, "clean" when it found nothing. Findings are split across the two
// arrays by the same floor that decides the exit code.
func NewReport(sbom *ossbom.SBOM) Report {
	r := Report{
		Verdict:    VerdictClean,
		Project:    sbom.Env.Project,
		Path:       sbom.Env.Path,
		Components: len(sbom.Components),
		Findings:   []Finding{},
	}
	for _, v := range sbom.Vulnerabilities {
		eco, name, version := parsePurl(v.Purl)
		f := Finding{
			Purl:        v.Purl,
			Ecosystem:   eco,
			Name:        name,
			Version:     version,
			ID:          v.ID,
			Type:        v.Type,
			Severity:    v.Severity,
			Description: v.Description,
			Reference:   v.Reference,
		}
		if severity.Parse(v.Severity).Fails() {
			r.Findings = append(r.Findings, f)
			continue
		}
		r.Informational = append(r.Informational, f)
	}
	switch {
	case len(r.Findings) > 0:
		r.Verdict = VerdictMalware
	case len(r.Informational) > 0:
		r.Verdict = VerdictInformational
	}
	return r
}

// SkippedReport summarises a scan the API declined to run (quota exhausted).
// The verdict is deliberately neither clean nor malware: nothing was checked,
// and a consumer must not report "no malware found" off the back of it.
func SkippedReport(sbom *ossbom.SBOM, message, resetAt string) Report {
	r := NewReport(sbom)
	r.Verdict = VerdictSkipped
	r.Skipped = &Skip{Message: message, ResetAt: resetAt}
	return r
}

// WriteReport writes r as JSON to path, creating parent directories.
func WriteReport(path string, r Report) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create report directory: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		f.Close()
		return fmt.Errorf("write report: %w", err)
	}
	// Closed explicitly rather than deferred, and its error is returned: this
	// file is what CI reads the verdict from, so a failed flush (a full disk,
	// say) has to surface instead of leaving a truncated report behind that
	// parses as something else.
	if err := f.Close(); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
