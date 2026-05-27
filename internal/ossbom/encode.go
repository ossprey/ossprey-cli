package ossbom

import (
	"encoding/json"
	"io"
)

func (s *SBOM) Encode(w io.Writer) error {
	s.Sort()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
