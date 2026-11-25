package netbird

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

type fakeDiscoveryClient struct {
	pkceFn   func(sessionExtend bool) (pkceAuthConfig, error)
	deviceFn func() (deviceAuthConfig, error)
}

func (f fakeDiscoveryClient) Close() error { return nil }
func (f fakeDiscoveryClient) GetPKCEAuthorizationFlow(sessionExtend bool) (pkceAuthConfig, error) {
	return f.pkceFn(sessionExtend)
}
func (f fakeDiscoveryClient) GetDeviceAuthorizationFlow() (deviceAuthConfig, error) {
	return f.deviceFn()
}

func TestStartOAuthSessionWithOptionsPriority(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"d1","user_code":"CODE-1","verification_uri_complete":"https://idp.example/d1"}`))
	}))
	defer srv.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	origDiscovery := newMgmDiscoveryClient
	defer func() { newMgmDiscoveryClient = origDiscovery }()

	// Case 1: PKCE is tried FIRST with sessionExtend=true when ExistingPrivateKey is set,
	// even if Device Flow is also available on the server.
	var deviceCalled atomic.Bool
	var gotSessionExtend atomic.Bool
	newMgmDiscoveryClient = func(ctx context.Context, host string, k wgtypes.Key, tlsEnabled bool) (oauthDiscoveryClient, error) {
		return fakeDiscoveryClient{
			pkceFn: func(sessionExtend bool) (pkceAuthConfig, error) {
				gotSessionExtend.Store(sessionExtend)
				return pkceAuthConfig{
					ClientID:              "cid",
					AuthorizationEndpoint: srv.URL + "/auth",
					TokenEndpoint:         srv.URL + "/token",
					RedirectURLs:          []string{"http://127.0.0.1:0/cb"},
				}, nil
			},
			deviceFn: func() (deviceAuthConfig, error) {
				deviceCalled.Store(true)
				return deviceAuthConfig{
					ClientID:           "cid",
					DeviceAuthEndpoint: srv.URL + "/device",
					TokenEndpoint:      srv.URL + "/token",
				}, nil
			},
		}, nil
	}

	res1, err := StartOAuthSessionWithOptions(context.Background(), OAuthStartOptions{
		ManagementURL:      "https://net.l0op.site",
		ExistingPrivateKey: key.String(),
	})
	if err != nil {
		t.Fatalf("Case 1 StartOAuthSessionWithOptions failed: %v", err)
	}
	defer CancelOAuthSession(res1.SessionID)
	if res1.FlowType != "pkce" {
		t.Fatalf("got FlowType %q, want pkce", res1.FlowType)
	}
	if !gotSessionExtend.Load() {
		t.Fatal("expected sessionExtend=true when ExistingPrivateKey is valid")
	}
	if deviceCalled.Load() {
		t.Fatal("expected Device Flow not to be called when PKCE succeeds")
	}

	// Case 2: PKCE NotFound falls back cleanly to Device Flow.
	newMgmDiscoveryClient = func(ctx context.Context, host string, k wgtypes.Key, tlsEnabled bool) (oauthDiscoveryClient, error) {
		return fakeDiscoveryClient{
			pkceFn: func(bool) (pkceAuthConfig, error) {
				return pkceAuthConfig{}, status.Error(codes.NotFound, "pkce disabled")
			},
			deviceFn: func() (deviceAuthConfig, error) {
				return deviceAuthConfig{
					ClientID:           "cid",
					DeviceAuthEndpoint: srv.URL + "/device",
					TokenEndpoint:      srv.URL + "/token",
				}, nil
			},
		}, nil
	}
	res2, err := StartOAuthSessionWithOptions(context.Background(), OAuthStartOptions{
		ManagementURL: "https://net.l0op.site",
	})
	if err != nil {
		t.Fatalf("Case 2 fallback failed: %v", err)
	}
	defer CancelOAuthSession(res2.SessionID)
	if res2.FlowType != "device" || res2.UserCode != "CODE-1" {
		t.Fatalf("unexpected fallback result: %+v", res2)
	}

	// Case 3: ForceDeviceFlow skips PKCE completely.
	var pkceCalled atomic.Bool
	newMgmDiscoveryClient = func(ctx context.Context, host string, k wgtypes.Key, tlsEnabled bool) (oauthDiscoveryClient, error) {
		return fakeDiscoveryClient{
			pkceFn: func(bool) (pkceAuthConfig, error) {
				pkceCalled.Store(true)
				return pkceAuthConfig{}, stderrors.New("should not call")
			},
			deviceFn: func() (deviceAuthConfig, error) {
				return deviceAuthConfig{
					ClientID:           "cid",
					DeviceAuthEndpoint: srv.URL + "/device",
					TokenEndpoint:      srv.URL + "/token",
				}, nil
			},
		}, nil
	}
	res3, err := StartOAuthSessionWithOptions(context.Background(), OAuthStartOptions{
		ManagementURL:   "https://net.l0op.site",
		ForceDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Case 3 ForceDeviceFlow failed: %v", err)
	}
	defer CancelOAuthSession(res3.SessionID)
	if pkceCalled.Load() {
		t.Fatal("expected PKCE not to be called when ForceDeviceFlow is true")
	}
	if res3.FlowType != "device" {
		t.Fatalf("got FlowType %q, want device", res3.FlowType)
	}
}

func TestCompleteOAuthSessionTransientRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"pkce-jwt","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	startRes, err := startPKCEOAuthSession("https://net.l0op.site", "net.l0op.site:443", true, key, pkceAuthConfig{
		ClientID:              "cid",
		AuthorizationEndpoint: srv.URL + "/auth",
		TokenEndpoint:         srv.URL + "/token",
		RedirectURLs:          []string{"http://127.0.0.1:0/cb"},
	})
	if err != nil {
		t.Fatalf("startPKCEOAuthSession: %v", err)
	}
	parsedAuth, _ := url.Parse(startRes.AuthURL)
	q := parsedAuth.Query()
	cbURL := fmt.Sprintf("%s?code=c1&state=%s", q.Get("redirect_uri"), url.QueryEscape(q.Get("state")))

	var attempts atomic.Int32
	origNewMgm := newMgmRegClient
	defer func() { newMgmRegClient = origNewMgm }()
	newMgmRegClient = func(ctx context.Context, host string, k wgtypes.Key, tlsEnabled bool) (mgmRegisterClient, error) {
		return fakeMgmRegClient{
			registerFn: func(setupKey, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (string, string, error) {
				if attempts.Add(1) == 1 {
					return "", "", status.Error(codes.Unavailable, "temporary disconnect")
				}
				return "100.77.2.3/16", "retry-node.net.loop", nil
			},
		}, nil
	}

	go func() {
		if resp, getErr := http.Get(cbURL); getErr == nil {
			resp.Body.Close()
		}
	}()

	completeRes, err := CompleteOAuthSession(context.Background(), startRes.SessionID, "retry-node")
	if err != nil {
		t.Fatalf("CompleteOAuthSession failed: %v", err)
	}
	if attempts.Load() != 2 || completeRes.PeerIP != "100.77.2.3/16" {
		t.Fatalf("unexpected retry result: attempts=%d res=%+v", attempts.Load(), completeRes)
	}
}
