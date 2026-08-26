package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// The verdicts a Report can carry. They are part of the file's contract with
// whatever reads it (the GitHub Action, other CI glue), so treat them as API.
const (
	VerdictClean   = "clean"
	VerdictMalware = "malware"
	VerdictSkipped = "skipped"
)

// Finding is one malicious package, pre-split so a consumer doesn't have to
// parse PURLs to render "name @ version".
type Finding struct {
	Purl        string `json:"purl"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	ID          string `json:"id,omitempty"`
	Type        string `json:"type,omitempty"`
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
// scan too.
type Report struct {
	Verdict    string    `json:"verdict"`
	Project    string    `json:"project,omitempty"`
	Path       string    `json:"path,omitempty"`
	Components int       `json:"components"`
	Findings   []Finding `json:"findings"`
	Skipped    *Skip     `json:"skipped,omitempty"`
}

// NewReport summarises a scanned SBOM: "malware" when it carries
// vulnerabilities, "clean" otherwise.
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
		r.Findings = append(r.Findings, Finding{
			Purl:        v.Purl,
			Ecosystem:   eco,
			Name:        name,
			Version:     version,
			ID:          v.ID,
			Type:        v.Type,
			Description: v.Description,
			Reference:   v.Reference,
		})
	}
	if len(r.Findings) > 0 {
		r.Verdict = VerdictMalware
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
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return f.Close()
}
