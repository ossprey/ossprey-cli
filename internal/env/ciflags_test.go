package env

import "testing"

func TestSkipCI(t *testing.T) {
	tests := map[string]bool{
		"":      false,
		"0":     false,
		"false": false,
		"no":    false,
		"off":   false,
		" 0 ":   false,
		"FALSE": false,
		"1":     true,
		"true":  true,
		"TRUE":  true,
		"yes":   true,
		"on":    true,
	}
	for in, want := range tests {
		t.Setenv(SkipCIEnv, in)
		if got := SkipCI(); got != want {
			t.Errorf("%s=%q: SkipCI() = %v, want %v", SkipCIEnv, in, got, want)
		}
	}
}

func TestCacheScanOnly(t *testing.T) {
	tests := map[string]bool{
		"":      false,
		"0":     false,
		"false": false,
		"1":     true,
		"true":  true,
	}
	for in, want := range tests {
		t.Setenv(CacheScanOnlyEnv, in)
		if got := CacheScanOnly(); got != want {
			t.Errorf("%s=%q: CacheScanOnly() = %v, want %v", CacheScanOnlyEnv, in, got, want)
		}
	}
}
