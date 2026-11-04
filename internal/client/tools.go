package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/anchore/packageurl-go"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// ErrNoRepoSBOM: the ingest mount has no tools route.
var ErrNoRepoSBOM = errors.New("repository SBOMs need an API key or login, not a monitor id")

// RepoSBOM asks the API to check out a repo purl (pkg:github/o/r@ref) and
// catalogue it. Returns the components, the repo's own code included.
func (c *Client) RepoSBOM(ctx context.Context, purl string) ([]ossbom.Component, error) {
	if c.IngestToken != "" {
		return nil, ErrNoRepoSBOM
	}
	endpoint, err := url.JoinPath(c.BaseURL, c.mount(), "tools/sbom")
	if err != nil {
		return nil, fmt.Errorf("build url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"?purl="+url.QueryEscape(purl), nil)
	if err != nil {
		return nil, err
	}
	c.authenticate(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("repo sbom: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, c.authError(resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("repo sbom failed (status %d): %s", resp.StatusCode, truncate(apiErrorMessage(body), 200))
	}
	var out struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode repo sbom: %w", err)
	}
	comps := make([]ossbom.Component, 0, len(out.Components))
	for _, c := range out.Components {
		if comp, ok := componentFromPurl(c.Purl); ok {
			comps = append(comps, comp)
		}
	}
	return comps, nil
}

// componentFromPurl reads a server purl; the purl is the one field /scans
// requires, so it is the one trusted here.
func componentFromPurl(raw string) (ossbom.Component, bool) {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Type == "" || p.Name == "" || p.Version == "" {
		return ossbom.Component{}, false
	}
	name := p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	c := ossbom.Component{Name: name, Version: p.Version, Type: p.Type, Source: []string{"repo-sbom"}}
	if q := p.Qualifiers.Map(); len(q) > 0 {
		c.Qualifiers = q
	}
	return c, true
}
