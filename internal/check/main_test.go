package check

import (
	"os"
	"testing"
)

// Run submits to httptest servers, which now also writes to the scan cache.
// Keep that out of the developer's real cache dir.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ossprey-check-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("OSSPREY_CACHE_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
