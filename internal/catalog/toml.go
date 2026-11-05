package catalog

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// maxManifestBytes bounds a TOML manifest to a size no genuine one reaches.
const maxManifestBytes = 1 << 20

// maxTOMLDepth bounds nesting, since the toml parser allocates quadratically in it (OSS-2098).
const maxTOMLDepth = 64

var (
	errTOMLTooDeep = fmt.Errorf("toml: nested deeper than %d levels", maxTOMLDepth)
	errNotRegular  = errors.New("not a regular file")
)

// readTOML reads a TOML manifest, refusing one too large to be genuine; its errors name path as given.
func readTOML(path string) ([]byte, error) {
	// A FIFO or device can block the open or never end, so only a regular file is opened.
	if info, err := os.Stat(path); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: path, Err: errNotRegular}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxManifestBytes {
		return nil, &fs.PathError{Op: "read", Path: path, Err: fmt.Errorf("%d bytes, over the %d byte limit", info.Size(), maxManifestBytes)}
	}
	// The size is only a hint: a device or a file still growing reads past it, so the read is bounded too.
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, &fs.PathError{Op: "read", Path: path, Err: fmt.Errorf("over the %d byte limit", maxManifestBytes)}
	}
	return data, nil
}

// relToRoot names the file in a path error relative to the scan root, so a warning points at one manifest in a monorepo.
func relToRoot(root string, err error) error {
	pe, ok := err.(*fs.PathError)
	if !ok {
		return err
	}
	for _, r := range []string{root, resolvedRoot(root)} {
		if rel, rerr := filepath.Rel(r, pe.Path); rerr == nil && filepath.IsLocal(rel) {
			return &fs.PathError{Op: pe.Op, Path: rel, Err: pe.Err}
		}
	}
	return err
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
