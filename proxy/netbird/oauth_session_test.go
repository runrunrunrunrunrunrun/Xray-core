package netbird

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
)

type fakeMgmRegClient struct {
	registerFn func(setupKey, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (string, string, error)
}

func (f fakeMgmRegClient) Close() error { return nil }

func (f fakeMgmRegClient) Register(setupKey, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (string, string, error) {
	return f.registerFn(setupKey, jwtToken, sysInfo, pubSSHKey)
}

func TestDeviceOAuthSessionLifecycle(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device":
			_, _ = w.Write([]byte(`{
				"device_code":"dev-1",
				"user_code":"WXYZ-1234",
				"verification_uri_complete":"https://idp.example/device?user_code=WXYZ-1234",
				"expires_in":30,
				"interval":1
			}`))
		case "/token":
			if polls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"jwt-session-tok","token_type":"Bearer"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	startRes, err := startDeviceOAuthSession(
		context.Background(),
		"https://net.l0op.site",
		"net.l0op.site:443",
		true,
		key,
		deviceAuthConfig{
			ClientID:           "cid",
			DeviceAuthEndpoint: srv.URL + "/device",
			TokenEndpoint:      srv.URL + "/token",
		},
		srv.Client(),
	)
	if err != nil {
		t.Fatalf("startDeviceOAuthSession failed: %v", err)
	}
	if startRes.UserCode != "WXYZ-1234" || startRes.FlowType != "device" {
		t.Fatalf("unexpected startRes: %+v", startRes)
	}

	origNewMgm := newMgmRegClient
	defer func() { newMgmRegClient = origNewMgm }()
	newMgmRegClient = func(ctx context.Context, host string, k wgtypes.Key, tlsEnabled bool) (mgmRegisterClient, error) {
		return fakeMgmRegClient{
			registerFn: func(setupKey, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (string, string, error) {
				if jwtToken != "jwt-session-tok" {
					t.Fatalf("unexpected jwtToken: %s", jwtToken)
				}
				if len(pubSSHKey) == 0 {
					t.Fatal("expected non-empty SSH public key")
				}
				return "100.77.1.2/16", "onexray-test.net.loop", nil
			},
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	completeRes, err := CompleteOAuthSession(ctx, startRes.SessionID, "onexray-test")
	if err != nil {
		t.Fatalf("CompleteOAuthSession failed: %v", err)
	}
	if completeRes.PrivateKey != key.String() || completeRes.PeerIP != "100.77.1.2/16" || completeRes.FQDN != "onexray-test.net.loop" {
		t.Fatalf("unexpected completeRes: %+v", completeRes)
	}
}

func TestPKCEOAuthSessionAndCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"pkce-jwt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	startRes, err := startPKCEOAuthSession("https://net.l0op.site", "net.l0op.site:443", true, key, pkceAuthConfig{
		ClientID:              "cid",
		AuthorizationEndpoint: srv.URL + "/auth",
		TokenEndpoint:         srv.URL + "/token",
		Scope:                 "openid",
		RedirectURLs:          []string{"http://127.0.0.1:0/callback"},
	})
	if err != nil {
		t.Fatalf("startPKCEOAuthSession failed: %v", err)
	}

	parsedAuth, err := url.Parse(startRes.AuthURL)
	if err != nil {
		t.Fatalf("parse AuthURL failed: %v", err)
	}
	q := parsedAuth.Query()
	cbURL := fmt.Sprintf("%s?code=c1&state=%s", q.Get("redirect_uri"), url.QueryEscape(q.Get("state")))

	origNewMgm := newMgmRegClient
	defer func() { newMgmRegClient = origNewMgm }()
	newMgmRegClient = func(ctx context.Context, host string, k wgtypes.Key, tlsEnabled bool) (mgmRegisterClient, error) {
		return fakeMgmRegClient{
			registerFn: func(setupKey, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (string, string, error) {
				return "100.77.9.9/16", "pkce-node.net.loop", nil
			},
		}, nil
	}

	go func() {
		resp, err := http.Get(cbURL)
		if err == nil {
			resp.Body.Close()
		}
	}()

	completeRes, err := CompleteOAuthSession(context.Background(), startRes.SessionID, "pkce-node")
	if err != nil {
		t.Fatalf("CompleteOAuthSession failed: %v", err)
	}
	if completeRes.PeerIP != "100.77.9.9/16" {
		t.Fatalf("unexpected completeRes: %+v", completeRes)
	}

	// Verify CancelOAuthSession cleans up pending session.
	s2, err := startPKCEOAuthSession("https://net.l0op.site", "net.l0op.site:443", true, key, pkceAuthConfig{
		ClientID:              "cid",
		AuthorizationEndpoint: srv.URL + "/auth",
		TokenEndpoint:         srv.URL + "/token",
		RedirectURLs:          []string{"http://127.0.0.1:0/callback"},
	})
	if err != nil {
		t.Fatalf("startPKCEOAuthSession s2 failed: %v", err)
	}
	CancelOAuthSession(s2.SessionID)
	if _, err := CompleteOAuthSession(context.Background(), s2.SessionID, "x"); err == nil {
		t.Fatal("expected error for cancelled session")
	}
}
