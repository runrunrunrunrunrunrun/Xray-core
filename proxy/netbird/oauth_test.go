package netbird

import (
	"context"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

func TestParseManagementURL(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantTLS  bool
		wantErr  bool
	}{
		{"", "api.netbird.io:443", true, false},
		{"https://net.l0op.site", "net.l0op.site:443", true, false},
		{"https://net.l0op.site:8443", "net.l0op.site:8443", true, false},
		{"http://localhost:8080", "localhost:8080", false, false},
		{"net.l0op.site", "net.l0op.site:443", true, false},
		{"ftp://net.l0op.site", "", false, true},
	}

	for _, tc := range tests {
		host, tlsEnabled, err := parseManagementURL(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseManagementURL(%q) err=%v, wantErr=%v", tc.raw, err, tc.wantErr)
		}
		if host != tc.wantHost || tlsEnabled != tc.wantTLS {
			t.Fatalf("parseManagementURL(%q) = (%q, %v), want (%q, %v)", tc.raw, host, tlsEnabled, tc.wantHost, tc.wantTLS)
		}
	}
}

func TestRunDeviceAuthFlow(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device":
			if r.Form.Get("client_id") != "cid" {
				t.Fatalf("unexpected client_id: %s", r.Form.Get("client_id"))
			}
			_, _ = w.Write([]byte(`{
				"device_code": "dev123",
				"user_code": "ABCD-EFGH",
				"verification_uri": "https://idp.example/activate",
				"verification_uri_complete": "https://idp.example/activate?user_code=ABCD-EFGH",
				"expires_in": 30,
				"interval": 1
			}`))
		case "/token":
			n := polls.Add(1)
			switch n {
			case 1:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			case 2:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
			default:
				_, _ = w.Write([]byte(`{"access_token":"acc-tok","id_token":"id-tok","token_type":"Bearer"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tok, err := runDeviceAuthFlow(context.Background(), deviceAuthConfig{
		ClientID:           "cid",
		DeviceAuthEndpoint: srv.URL + "/device",
		TokenEndpoint:      srv.URL + "/token",
		UseIDToken:         true,
	}, srv.Client())
	if err != nil {
		t.Fatalf("runDeviceAuthFlow failed: %v", err)
	}
	if tok != "id-tok" {
		t.Fatalf("got token %q, want %q", tok, "id-tok")
	}
}

func TestRunPKCEAuthFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}
		if r.Form.Get("code") != "auth-code-1" || r.Form.Get("code_verifier") == "" {
			t.Fatalf("missing code or code_verifier: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"pkce-access","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	origStderr := os.Stderr
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stderr = wPipe
	defer func() { os.Stderr = origStderr }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		tok string
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		tok, err := runPKCEAuthFlow(ctx, pkceAuthConfig{
			ClientID:              "cid",
			AuthorizationEndpoint: srv.URL + "/authorize",
			TokenEndpoint:         srv.URL + "/token",
			Scope:                 "openid profile",
			RedirectURLs:          []string{"http://127.0.0.1:0/callback"},
		})
		resCh <- result{tok, err}
	}()

	buf := make([]byte, 4096)
	n, err := rPipe.Read(buf)
	_ = wPipe.Close()
	_ = rPipe.Close()
	if err != nil {
		t.Fatalf("reading stderr failed: %v", err)
	}
	line := string(buf[:n])
	idx := strings.Index(line, "http://")
	if idx < 0 {
		t.Fatalf("expected auth URL on stderr, got %q", line)
	}
	authURLStr := strings.Fields(line[idx:])[0]
	parsedAuth, err := url.Parse(authURLStr)
	if err != nil {
		t.Fatalf("parse auth URL %q: %v", authURLStr, err)
	}
	q := parsedAuth.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if redirectURI == "" || state == "" {
		t.Fatalf("missing redirect_uri or state in %q", authURLStr)
	}

	callbackURL := fmt.Sprintf("%s?code=auth-code-1&state=%s", redirectURI, url.QueryEscape(state))
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	resp.Body.Close()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("runPKCEAuthFlow failed: %v", res.err)
	}
	if res.tok != "pkce-access" {
		t.Fatalf("got token %q, want %q", res.tok, "pkce-access")
	}
}

func TestHandlerOAuthLifecycle(t *testing.T) {
	pm := newTestPolicyManager(t)

	// Case 1: Fresh OAuth login passes JWT token to embed.Options.
	var gotOpts embed.Options
	client := &fakeNetbirdClient{}
	h := newOAuthHandler(
		pm,
		embed.Options{DeviceName: "oauth-node"},
		"https://net.l0op.site",
		"",
		time.Second,
		5*time.Second,
		nil,
		nil,
		func(opts embed.Options) (netbirdClient, error) {
			gotOpts = opts
			return client, nil
		},
		func(ctx context.Context, mgmtURL, existingPrivKey string) (string, error) {
			if mgmtURL != "https://net.l0op.site" {
				t.Fatalf("unexpected managementURL: %s", mgmtURL)
			}
			return "fresh-jwt-token", nil
		},
		true,
	)
	if err := h.ensureStarted(context.Background()); err != nil {
		t.Fatalf("ensureStarted failed: %v", err)
	}
	if gotOpts.JWTToken != "fresh-jwt-token" || gotOpts.PrivateKey != "" {
		t.Fatalf("unexpected embed.Options: %+v", gotOpts)
	}
	_ = h.Close()

	// Case 2: Persisted configPath with PrivateKey logs in silently without calling OAuth.
	cfgPath := filepath.Join(t.TempDir(), "nb.json")
	if err := os.WriteFile(cfgPath, []byte(`{"PrivateKey":"saved-wg-key"}`), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	var oauthCalled atomic.Bool
	var silentOpts embed.Options
	h2 := newOAuthHandler(
		pm,
		embed.Options{ConfigPath: cfgPath},
		"https://net.l0op.site",
		cfgPath,
		time.Second,
		5*time.Second,
		nil,
		nil,
		func(opts embed.Options) (netbirdClient, error) {
			silentOpts = opts
			return &fakeNetbirdClient{}, nil
		},
		func(ctx context.Context, mgmtURL, existingPrivKey string) (string, error) {
			oauthCalled.Store(true)
			return "should-not-be-used", nil
		},
		true,
	)
	if err := h2.ensureStarted(context.Background()); err != nil {
		t.Fatalf("ensureStarted failed: %v", err)
	}
	if oauthCalled.Load() {
		t.Fatal("expected silent login without OAuth call")
	}
	if silentOpts.PrivateKey != "saved-wg-key" || silentOpts.JWTToken != "" {
		t.Fatalf("unexpected silent embed.Options: %+v", silentOpts)
	}
	_ = h2.Close()

	// Case 3: Expired persisted key falls back to interactive OAuth.
	var attempts atomic.Int32
	var fallbackOpts embed.Options
	h3 := newOAuthHandler(
		pm,
		embed.Options{ConfigPath: cfgPath},
		"https://net.l0op.site",
		cfgPath,
		time.Second,
		5*time.Second,
		nil,
		nil,
		func(opts embed.Options) (netbirdClient, error) {
			if attempts.Add(1) == 1 {
				return &fakeNetbirdClient{
					startFn: func(context.Context) error {
						return stderrors.New("peer login has expired")
					},
				}, nil
			}
			fallbackOpts = opts
			return &fakeNetbirdClient{}, nil
		},
		func(ctx context.Context, mgmtURL, existingPrivKey string) (string, error) {
			if existingPrivKey != "saved-wg-key" {
				t.Fatalf("expected existingPrivKey passed to OAuth, got %q", existingPrivKey)
			}
			return "renewed-jwt", nil
		},
		true,
	)
	if err := h3.ensureStarted(context.Background()); err != nil {
		t.Fatalf("ensureStarted fallback failed: %v", err)
	}
	if fallbackOpts.JWTToken != "renewed-jwt" || fallbackOpts.PrivateKey != "" {
		t.Fatalf("unexpected fallback embed.Options: %+v", fallbackOpts)
	}
	_ = h3.Close()

	// Case 4: Close cancels in-flight OAuth wait immediately.
	waiting := make(chan struct{})
	h4 := newOAuthHandler(
		pm,
		embed.Options{},
		"https://net.l0op.site",
		"",
		time.Second,
		30*time.Second,
		nil,
		nil,
		func(opts embed.Options) (netbirdClient, error) {
			return &fakeNetbirdClient{}, nil
		},
		func(ctx context.Context, mgmtURL, existingPrivKey string) (string, error) {
			close(waiting)
			<-ctx.Done()
			return "", ctx.Err()
		},
		true,
	)
	<-waiting
	startClose := time.Now()
	if err := h4.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if time.Since(startClose) > time.Second {
		t.Fatalf("Close took too long: %v", time.Since(startClose))
	}
}

func makeTestJWT(claimsJSON string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return hdr + "." + pay + ".sig"
}

func TestValidateTokenAudience(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		aud     string
		wantErr bool
	}{
		{"string aud match", makeTestJWT(`{"aud":"https://api.netbird.io"}`), "https://api.netbird.io", false},
		{"array aud match", makeTestJWT(`{"aud":["other","https://api.netbird.io"]}`), "https://api.netbird.io", false},
		{"aud mismatch", makeTestJWT(`{"aud":"https://wrong.example"}`), "https://api.netbird.io", true},
		{"missing aud", makeTestJWT(`{"sub":"123"}`), "https://api.netbird.io", true},
		{"malformed jwt", "not-a-jwt", "https://api.netbird.io", true},
		{"empty token", "", "https://api.netbird.io", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenAudience(tc.token, tc.aud)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateTokenAudience() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestParseExcludedPortRanges(t *testing.T) {
	englishOutput := `
Protocol tcp Port Exclusion Ranges

Start Port    End Port
----------    --------
     49675       49774
     50000       50059     *
     53000       53099

* - Administered port exclusions.
`
	chineseOutput := `
协议 tcp 端口排除范围

开始端口    结束端口
----------    --------
     49664       49763
     53000       53099
`
	wantEN := []excludedPortRange{{49675, 49774}, {50000, 50059}, {53000, 53099}}
	if got := parseExcludedPortRanges(englishOutput); !reflect.DeepEqual(got, wantEN) {
		t.Fatalf("English netsh parse = %+v, want %+v", got, wantEN)
	}
	wantZH := []excludedPortRange{{49664, 49763}, {53000, 53099}}
	if got := parseExcludedPortRanges(chineseOutput); !reflect.DeepEqual(got, wantZH) {
		t.Fatalf("Chinese netsh parse = %+v, want %+v", got, wantZH)
	}
	if !isPortExcluded(50000, wantEN) || isPortExcluded(54000, wantEN) {
		t.Fatal("isPortExcluded returned unexpected result")
	}
}
