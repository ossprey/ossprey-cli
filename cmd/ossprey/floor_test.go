package main

import (
	"testing"

	"github.com/ossprey/ossprey-cli/internal/severity"
)

func TestParseFloorOverride(t *testing.T) {
	tests := []struct {
		name                string
		failOn              string
		failOnInformational bool
		want                severity.Level
		wantErr             bool
	}{
		{name: "no flags leaves the account's floor in charge", want: severity.Unknown},
		{name: "the shorthand is the bottom of the scale", failOnInformational: true, want: severity.Info},
		{name: "an explicit level", failOn: "Critical", want: severity.Critical},
		{name: "casing is the wire's problem, not the user's", failOn: "high", want: severity.High},
		{name: "the explicit level wins over the shorthand", failOn: "Medium", failOnInformational: true, want: severity.Medium},
		{name: "a typo is an error, not a silent default", failOn: "Bananas", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFloorOverride(tt.failOn, tt.failOnInformational)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err: got %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// Most specific wins, not strictest: taking the lower of the two would discard
// an override raised for one run, which is the commonest reason to set one.
func TestResolveFloor(t *testing.T) {
	tests := []struct {
		name     string
		served   string
		override severity.Level
		want     severity.Level
	}{
		{name: "nothing served, no override", want: severity.FailingFloor},
		{name: "the account's floor applies", served: "High", want: severity.High},
		{name: "an unreadable floor is the default, not a failure", served: "Banana", want: severity.FailingFloor},
		{name: "an override raises past the account", served: "Low", override: severity.Critical, want: severity.Critical},
		{name: "an override lowers past the account", served: "Critical", override: severity.Info, want: severity.Info},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveFloor(tt.served, tt.override); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
