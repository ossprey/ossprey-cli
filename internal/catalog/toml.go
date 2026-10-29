package catalog

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// maxManifestBytes bounds a TOML manifest to a size no genuine one reaches.
const maxManifestBytes = 1 << 20

// maxTOMLDepth bounds nesting, since the toml parser allocates quadratically in it (OSS-2098).
const maxTOMLDepth = 64

var errTOMLTooDeep = fmt.Errorf("toml: nested deeper than %d levels", maxTOMLDepth)

// readTOML reads a TOML manifest, refusing one too large to be genuine.
func readTOML(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d limit", filepath.Base(path), info.Size(), maxManifestBytes)
	}
	return os.ReadFile(path)
}

// decodeTOML decodes data into v, refusing data nested deeper than maxTOMLDepth.
func decodeTOML(data []byte, v any) (toml.MetaData, error) {
	if err := checkTOMLDepth(data); err != nil {
		return toml.MetaData{}, err
	}
	return toml.Decode(string(data), v)
}

// checkTOMLDepth sums the dots outside strings and comments with the open brackets, never counting below the parser.
func checkTOMLDepth(data []byte) error {
	var (
		open     []int // dots in force when each open { or [ began
		header   int   // dots in the current [table] header
		dots     int   // dots in the current statement
		inHeader bool
		inValue  bool // past the = of a top-level statement
	)
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"', '\'':
			i = skipTOMLString(data, i)
		case '#':
			for i+1 < len(data) && data[i+1] != '\n' && data[i+1] != '\r' {
				i++
			}
		case '\n', '\r':
			if len(open) == 0 {
				dots, inHeader, inValue = 0, false, false
			}
		case '=':
			if len(open) == 0 {
				inValue = true
			}
		case '.':
			if inHeader {
				header++
			} else {
				dots++
			}
		case '[':
			if len(open) == 0 && !inValue {
				if !inHeader {
					inHeader, header = true, 0
				}
				break
			}
			open = append(open, dots)
		case '{':
			open = append(open, dots)
		case ']', '}':
			if inHeader {
				inHeader = false
			} else if len(open) > 0 {
				dots, open = open[len(open)-1], open[:len(open)-1]
			}
		case ',':
			if len(open) > 0 {
				dots = open[len(open)-1]
			}
		}
		if header+dots+len(open) > maxTOMLDepth {
			return errTOMLTooDeep
		}
	}
	return nil
}

// skipTOMLString returns the index of the last byte of the string opening at data[i].
func skipTOMLString(data []byte, i int) int {
	q := data[i]
	if i+2 < len(data) && data[i+1] == q && data[i+2] == q {
		for j := i + 3; j < len(data); j++ {
			if q == '"' && data[j] == '\\' {
				j++
				continue
			}
			if j+2 < len(data) && data[j] == q && data[j+1] == q && data[j+2] == q {
				// Up to two quotes before the closing three belong to the string.
				for j+3 < len(data) && data[j+3] == q {
					j++
				}
				return j + 2
			}
		}
		return len(data)
	}
	for j := i + 1; j < len(data); j++ {
		switch {
		case data[j] == '\n' || data[j] == '\r':
			return j - 1
		case q == '"' && data[j] == '\\':
			j++
		case data[j] == q:
			return j
		}
	}
	return len(data)
}
