package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func sessionIDToken(email string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"email":"`+email+`","sub":"auth0|1"}`)) + ".sig"
}

// Session hands back the whole credential, not just the access token, so a
// caller can read the identity the login belongs to.
func TestSessionReturnsTheValidStoredLogin(t *testing.T) {
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	if err := Save(&Credentials{
		AccessToken: "at-stored",
		IDToken:     sessionIDToken("dev@ossprey.com"),
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	creds, err := Session(context.Background(), nil)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if creds.AccessToken != "at-stored" {
		t.Errorf("access token = %q", creds.AccessToken)
	}
	if got := creds.Identity(); got != "dev@ossprey.com" {
		t.Errorf("identity = %q", got)
	}
	// AccessToken is the same session seen through a narrower window.
	if tok, err := AccessToken(context.Background(), nil); err != nil || tok != "at-stored" {
		t.Errorf("AccessToken = %q, %v", tok, err)
	}
}

// Subject is the Auth0 account id (the sub claim), the one identifier that is
// unique and stable for a login; email is only unique within a connection.
func TestSubjectReadsTheSubClaim(t *testing.T) {
	c := &Credentials{IDToken: sessionIDToken("dev@ossprey.com")}
	if got := c.Subject(); got != "auth0|1" {
		t.Errorf("Subject() = %q, want auth0|1", got)
	}
	if got := (&Credentials{}).Subject(); got != "" {
		t.Errorf("Subject() with no ID token = %q, want empty", got)
	}
	if got := (&Credentials{IDToken: "not.a.jwt"}).Subject(); got != "" {
		t.Errorf("Subject() with a malformed token = %q, want empty", got)
	}
}

func TestSessionWhenNotLoggedIn(t *testing.T) {
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	if _, err := Session(context.Background(), nil); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("Session with no login: %v, want ErrNotLoggedIn", err)
	}
}
