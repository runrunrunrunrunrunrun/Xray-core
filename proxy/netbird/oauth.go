package netbird

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmcommon "github.com/netbirdio/netbird/shared/management/client/common"
	"github.com/netbirdio/netbird/util/embeddedroots"
	"github.com/xtls/xray-core/common/log"
)

const (
	deviceFlowGrantType  = "urn:ietf:params:oauth:grant-type:device_code"
	defaultOAuthTimeout  = 5 * time.Minute
	defaultManagementURL = "https://api.netbird.io:443"
)

type deviceAuthConfig struct {
	ClientID           string
	ClientSecret       string
	Audience           string
	TokenEndpoint      string
	DeviceAuthEndpoint string
	Scope              string
	UseIDToken         bool
}

type pkceAuthConfig struct {
	ClientID              string
	ClientSecret          string
	Audience              string
	TokenEndpoint         string
	AuthorizationEndpoint string
	Scope                 string
	RedirectURLs          []string
	UseIDToken            bool
	DisablePromptLogin    bool
	LoginFlag             mgmcommon.LoginFlag
	LoginHint             string
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

type deviceTokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func newOAuthHTTPClient(timeout time.Duration) *http.Client {
	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		certPool = embeddedroots.Get()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs: certPool,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func parseManagementURL(raw string) (host string, tlsEnabled bool, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		trimmed = defaultManagementURL
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", false, fmt.Errorf("parse management URL: %w", err)
	}
	if u.Hostname() == "" {
		return "", false, fmt.Errorf("management URL %q missing host", raw)
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		tlsEnabled = true
	case "http":
		tlsEnabled = false
	default:
		return "", false, fmt.Errorf("unsupported management URL scheme %q", u.Scheme)
	}

	port := u.Port()
	if port == "" {
		if tlsEnabled {
			port = "443"
		} else {
			port = "80"
		}
	}

	return net.JoinHostPort(u.Hostname(), port), tlsEnabled, nil
}

func readPrivateKeyFromConfig(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg struct {
		PrivateKey string `json:"PrivateKey"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.PrivateKey)
}

func notifyOAuthURL(authURL, userCode string) {
	msg := fmt.Sprintf("NetBird OAuth login required. Open URL in browser: %s", authURL)
	if userCode != "" {
		msg = fmt.Sprintf("NetBird OAuth login required. Open URL in browser: %s (user code: %s)", authURL, userCode)
	}
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Warning,
		Content:  "netbird: " + msg,
	})
	fmt.Fprintln(os.Stderr, msg)
}

func validatePKCEConfig(cfg pkceAuthConfig) error {
	if cfg.ClientID == "" || cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || len(cfg.RedirectURLs) == 0 {
		return errors.New("incomplete PKCE authorization flow config from management server")
	}
	return nil
}

func validateDeviceAuthConfig(cfg deviceAuthConfig) error {
	if cfg.ClientID == "" || cfg.DeviceAuthEndpoint == "" || cfg.TokenEndpoint == "" {
		return errors.New("incomplete device authorization flow config from management server")
	}
	return nil
}

// validateTokenAudience mirrors NetBird client/internal/auth/util.go:validateTokenAudience.
func validateTokenAudience(token, audience string) error {
	if token == "" {
		return errors.New("token received is empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token is not a well-formed JWT")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var claims struct {
		Audience any `json:"aud"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return err
	}
	if claims.Audience == nil {
		return errors.New("required token field audience is absent")
	}
	switch aud := claims.Audience.(type) {
	case string:
		if aud == audience {
			return nil
		}
	case []any:
		for _, item := range aud {
			if audStr, ok := item.(string); ok && audStr == audience {
				return nil
			}
		}
	}
	return errors.New("invalid JWT token audience field")
}

func selectToken(accessToken, idToken string, useIDToken bool, audience string) (string, error) {
	token := accessToken
	if useIDToken {
		token = idToken
	}
	if token == "" {
		return "", errors.New("oauth flow returned empty token")
	}
	if audience != "" {
		if err := validateTokenAudience(token, audience); err != nil {
			return "", fmt.Errorf("validate token audience: %w", err)
		}
	}
	return token, nil
}

func obtainOAuthToken(ctx context.Context, managementURL, existingPrivateKey string) (string, error) {
	host, tlsEnabled, err := parseManagementURL(managementURL)
	if err != nil {
		return "", err
	}

	trimmedExisting := strings.TrimSpace(existingPrivateKey)
	sessionExtend := trimmedExisting != ""

	var key wgtypes.Key
	if sessionExtend {
		key, err = wgtypes.ParseKey(trimmedExisting)
	}
	if !sessionExtend || err != nil {
		sessionExtend = false
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", fmt.Errorf("generate temporary wireguard key: %w", err)
		}
	}

	mgmClient, err := mgm.NewClient(ctx, host, key, tlsEnabled)
	if err != nil {
		return "", fmt.Errorf("connect management server %s: %w", host, err)
	}
	defer mgmClient.Close()

	// Official NetBird order: try PKCE Authorization Code Flow first, fall back to Device Code Flow.
	pkceFlow, pkceErr := mgmClient.GetPKCEAuthorizationFlow(sessionExtend)
	if pkceErr == nil && pkceFlow != nil && pkceFlow.GetProviderConfig() != nil {
		p := pkceFlow.GetProviderConfig()
		tok, flowErr := runPKCEAuthFlow(ctx, pkceAuthConfig{
			ClientID:              p.GetClientID(),
			ClientSecret:          p.GetClientSecret(), //nolint:staticcheck
			Audience:              p.GetAudience(),
			TokenEndpoint:         p.GetTokenEndpoint(),
			AuthorizationEndpoint: p.GetAuthorizationEndpoint(),
			Scope:                 p.GetScope(),
			RedirectURLs:          p.GetRedirectURLs(),
			UseIDToken:            p.GetUseIDToken(),
			DisablePromptLogin:    p.GetDisablePromptLogin(),
			LoginFlag:             mgmcommon.LoginFlag(p.GetLoginFlag()),
		})
		if flowErr == nil {
			return tok, nil
		}
		pkceErr = flowErr
	}

	deviceFlow, deviceErr := mgmClient.GetDeviceAuthorizationFlow()
	if deviceErr == nil && deviceFlow != nil && deviceFlow.GetProviderConfig() != nil {
		p := deviceFlow.GetProviderConfig()
		return runDeviceAuthFlow(ctx, deviceAuthConfig{
			ClientID:           p.GetClientID(),
			ClientSecret:       p.GetClientSecret(), //nolint:staticcheck
			Audience:           p.GetAudience(),
			TokenEndpoint:      p.GetTokenEndpoint(),
			DeviceAuthEndpoint: p.GetDeviceAuthEndpoint(),
			Scope:              p.GetScope(),
			UseIDToken:         p.GetUseIDToken(),
		}, nil)
	}

	if s, ok := status.FromError(deviceErr); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
		return "", fmt.Errorf("no SSO provider returned from management %s (pkce: %v; device: %w)", managementURL, pkceErr, deviceErr)
	}
	if pkceErr != nil {
		return "", fmt.Errorf("get oauth flow (pkce: %v; device: %w)", pkceErr, deviceErr)
	}
	return "", fmt.Errorf("get device authorization flow: %w", deviceErr)
}

func runDeviceAuthFlow(ctx context.Context, cfg deviceAuthConfig, httpClient *http.Client) (string, error) {
	if err := validateDeviceAuthConfig(cfg); err != nil {
		return "", err
	}
	if httpClient == nil {
		httpClient = newOAuthHTTPClient(15 * time.Second)
	}

	scope := strings.TrimSpace(cfg.Scope)
	if scope == "" {
		scope = "openid"
	}

	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("scope", scope)
	if cfg.Audience != "" {
		form.Set("audience", cfg.Audience)
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.DeviceAuthEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request device code: %w", err)
	}
	body, readErr := io.ReadAll(res.Body)
	res.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("read device code response: %w", readErr)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("device code request failed (%d): %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var codeResp deviceCodeResponse
	if err := json.Unmarshal(body, &codeResp); err != nil {
		return "", fmt.Errorf("parse device code response: %w", err)
	}
	if codeResp.Error != "" {
		return "", fmt.Errorf("device code error %s: %s", codeResp.Error, codeResp.ErrorDescription)
	}
	if codeResp.DeviceCode == "" {
		return "", errors.New("device code response missing device_code")
	}

	verifyURL := codeResp.VerificationURIComplete
	if verifyURL == "" {
		verifyURL = codeResp.VerificationURI
	}
	if verifyURL == "" {
		return "", errors.New("device code response missing verification URI")
	}

	expiresIn := codeResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int(defaultOAuthTimeout.Seconds())
	}
	interval := time.Duration(codeResp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	notifyOAuthURL(verifyURL, codeResp.UserCode)

	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(expiresIn)*time.Second)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return "", waitCtx.Err()
		case <-ticker.C:
			tokResp, err := pollDeviceToken(waitCtx, httpClient, cfg, codeResp.DeviceCode)
			if err != nil {
				return "", err
			}
			if tokResp.Error != "" {
				switch tokResp.Error {
				case "authorization_pending":
					continue
				case "slow_down":
					interval += 3 * time.Second
					ticker.Reset(interval)
					continue
				default:
					if tokResp.ErrorDescription != "" {
						return "", fmt.Errorf("device flow failed (%s): %s", tokResp.Error, tokResp.ErrorDescription)
					}
					return "", fmt.Errorf("device flow failed: %s", tokResp.Error)
				}
			}

			return selectToken(tokResp.AccessToken, tokResp.IDToken, cfg.UseIDToken, cfg.Audience)
		}
	}
}

func pollDeviceToken(ctx context.Context, httpClient *http.Client, cfg deviceAuthConfig, deviceCode string) (deviceTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", deviceFlowGrantType)
	form.Set("client_id", cfg.ClientID)
	form.Set("device_code", deviceCode)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return deviceTokenResponse{}, fmt.Errorf("create device token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return deviceTokenResponse{}, fmt.Errorf("request device token: %w", err)
	}
	body, readErr := io.ReadAll(res.Body)
	res.Body.Close()
	if readErr != nil {
		return deviceTokenResponse{}, fmt.Errorf("read device token response: %w", readErr)
	}
	if res.StatusCode >= http.StatusInternalServerError {
		return deviceTokenResponse{}, fmt.Errorf("token endpoint error (%d): %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokResp deviceTokenResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return deviceTokenResponse{}, fmt.Errorf("parse device token response: %w", err)
	}
	return tokResp, nil
}

func buildPKCEOAuthConfigAndURL(cfg pkceAuthConfig, redirectURL, state, codeVerifier string) (*oauth2.Config, string) {
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	scopes := strings.Fields(cfg.Scope)
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthorizationEndpoint,
			TokenURL: cfg.TokenEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
	}
	if cfg.Audience != "" {
		params = append(params, oauth2.SetAuthURLParam("audience", cfg.Audience))
	}
	if !cfg.DisablePromptLogin {
		switch cfg.LoginFlag {
		case mgmcommon.LoginFlagPromptLogin:
			params = append(params, oauth2.SetAuthURLParam("prompt", "login"))
		case mgmcommon.LoginFlagMaxAge0:
			params = append(params, oauth2.SetAuthURLParam("max_age", "0"))
		}
	}
	if cfg.LoginHint != "" {
		params = append(params, oauth2.SetAuthURLParam("login_hint", cfg.LoginHint))
	}

	return oauthCfg, oauthCfg.AuthCodeURL(state, params...)
}

func runPKCEAuthFlow(ctx context.Context, cfg pkceAuthConfig) (string, error) {
	if err := validatePKCEConfig(cfg); err != nil {
		return "", err
	}

	ln, redirectURL, err := bindPKCERedirectListener(cfg.RedirectURLs)
	if err != nil {
		return "", err
	}
	defer ln.Close()

	state, err := randomHexBytes(24)
	if err != nil {
		return "", fmt.Errorf("generate PKCE state: %w", err)
	}
	codeVerifier, err := randomHexBytes(32)
	if err != nil {
		return "", fmt.Errorf("generate PKCE verifier: %w", err)
	}

	oauthCfg, authURL := buildPKCEOAuthConfigAndURL(cfg, redirectURL, state, codeVerifier)
	notifyOAuthURL(authURL, "")

	waitCtx, cancel := context.WithTimeout(ctx, defaultOAuthTimeout)
	defer cancel()

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)
	httpClient := newOAuthHTTPClient(15 * time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		handlePKCECallback(w, req, state, codeVerifier, cfg, oauthCfg, httpClient, tokenCh, errCh)
	})

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			select {
			case errCh <- serveErr:
			default:
			}
		}
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(shutdownCtx)
		shutdownCancel()
	}()

	select {
	case <-waitCtx.Done():
		return "", waitCtx.Err()
	case err := <-errCh:
		return "", err
	case tok := <-tokenCh:
		return tok, nil
	}
}

func handlePKCECallback(
	w http.ResponseWriter,
	req *http.Request,
	state, codeVerifier string,
	cfg pkceAuthConfig,
	oauthCfg *oauth2.Config,
	httpClient *http.Client,
	tokenCh chan<- string,
	errCh chan<- error,
) {
	q := req.URL.Query()
	if authErr := q.Get("error"); authErr != "" {
		desc := q.Get("error_description")
		if desc != "" {
			authErr = desc
		}
		writePKCEResponse(w, http.StatusBadRequest, "NetBird login failed: "+authErr)
		select {
		case errCh <- fmt.Errorf("PKCE authorization error: %s", authErr):
		default:
		}
		return
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(q.Get("state"))) == 0 {
		writePKCEResponse(w, http.StatusBadRequest, "NetBird login failed: invalid state")
		select {
		case errCh <- errors.New("PKCE authorization failed: invalid state"):
		default:
		}
		return
	}
	code := q.Get("code")
	if code == "" {
		writePKCEResponse(w, http.StatusBadRequest, "NetBird login failed: missing authorization code")
		select {
		case errCh <- errors.New("PKCE authorization failed: missing code"):
		default:
		}
		return
	}

	exchangeCtx := context.WithValue(req.Context(), oauth2.HTTPClient, httpClient)
	tok, exchangeErr := oauthCfg.Exchange(exchangeCtx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if exchangeErr != nil {
		writePKCEResponse(w, http.StatusBadGateway, "NetBird token exchange failed: "+exchangeErr.Error())
		select {
		case errCh <- fmt.Errorf("PKCE token exchange: %w", exchangeErr):
		default:
		}
		return
	}

	idTok, _ := tok.Extra("id_token").(string)
	selected, selErr := selectToken(tok.AccessToken, idTok, cfg.UseIDToken, cfg.Audience)
	if selErr != nil {
		writePKCEResponse(w, http.StatusBadGateway, "NetBird token validation failed: "+selErr.Error())
		select {
		case errCh <- selErr:
		default:
		}
		return
	}

	writePKCEResponse(w, http.StatusOK, "NetBird login successful. You can close this window.")
	select {
	case tokenCh <- selected:
	default:
	}
}

func bindPKCERedirectListener(redirectURLs []string) (net.Listener, string, error) {
	excludedRanges := getSystemExcludedPortRanges()
	var lastErr error
	for _, raw := range redirectURLs {
		u, err := url.Parse(raw)
		if err != nil {
			lastErr = err
			continue
		}
		port := u.Port()
		if port == "" {
			switch strings.ToLower(u.Scheme) {
			case "http":
				port = "80"
			case "https":
				port = "443"
			}
		}
		if port == "" {
			continue
		}
		if p, convErr := strconv.Atoi(port); convErr == nil && p > 0 && isPortExcluded(p, excludedRanges) {
			lastErr = fmt.Errorf("redirect port %d is excluded by Windows", p)
			continue
		}

		var addrs []string
		switch strings.ToLower(u.Hostname()) {
		case "127.0.0.1":
			addrs = []string{net.JoinHostPort("127.0.0.1", port)}
		case "::1":
			addrs = []string{net.JoinHostPort("::1", port)}
		case "localhost", "":
			addrs = []string{
				net.JoinHostPort("", port),
				net.JoinHostPort("127.0.0.1", port),
			}
		default:
			addrs = []string{net.JoinHostPort("", port)}
		}
		var ln net.Listener
		for _, listenAddr := range addrs {
			ln, err = net.Listen("tcp", listenAddr)
			if err == nil {
				break
			}
		}
		if err != nil {
			lastErr = err
			continue
		}
		if port == "0" {
			if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
				host := u.Hostname()
				if host == "" {
					host = "localhost"
				}
				u.Host = net.JoinHostPort(host, fmt.Sprintf("%d", tcpAddr.Port))
			}
		}
		return ln, u.String(), nil
	}
	if lastErr != nil {
		return nil, "", fmt.Errorf("bind PKCE redirect listener: %w", lastErr)
	}
	return nil, "", fmt.Errorf("no usable PKCE redirect URL in %q", redirectURLs)
}

func writePKCEResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, "<!doctype html><html><body><h3>%s</h3></body></html>", html.EscapeString(message))
}

func randomHexBytes(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
