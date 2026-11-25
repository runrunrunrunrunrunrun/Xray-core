package netbird

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmcommon "github.com/netbirdio/netbird/shared/management/client/common"
)

// OAuthStartResult describes an in-progress interactive NetBird OAuth session.
type OAuthStartResult struct {
	SessionID string `json:"sessionId"`
	AuthURL   string `json:"authUrl"`
	UserCode  string `json:"userCode,omitempty"`
	FlowType  string `json:"flowType"`
	ExpiresIn int    `json:"expiresIn"`
}

// OAuthCompleteResult holds the registered NetBird peer identity after OAuth succeeds.
type OAuthCompleteResult struct {
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	PeerIP        string `json:"peerIp,omitempty"`
	FQDN          string `json:"fqdn,omitempty"`
	ManagementURL string `json:"managementUrl"`
}

type oauthSession struct {
	id            string
	managementURL string
	host          string
	tlsEnabled    bool
	key           wgtypes.Key
	flowType      string
	waitToken     func(ctx context.Context) (string, error)
	cancel        context.CancelFunc
	cleanup       func()
}

type mgmRegisterClient interface {
	Close() error
	Register(setupKey string, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (peerIP, fqdn string, err error)
}

type realMgmRegisterClient struct {
	*mgm.GrpcClient
}

func (c realMgmRegisterClient) Register(setupKey string, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (string, string, error) {
	resp, err := c.GrpcClient.Register(setupKey, jwtToken, sysInfo, pubSSHKey, nil)
	if err != nil {
		return "", "", err
	}
	if resp == nil || resp.GetPeerConfig() == nil {
		return "", "", nil
	}
	return resp.GetPeerConfig().GetAddress(), resp.GetPeerConfig().GetFqdn(), nil
}

var (
	oauthSessionsMu sync.Mutex
	oauthSessions   = make(map[string]*oauthSession)
	newMgmRegClient = func(ctx context.Context, host string, key wgtypes.Key, tlsEnabled bool) (mgmRegisterClient, error) {
		c, err := mgm.NewClient(ctx, host, key, tlsEnabled)
		if err != nil {
			return nil, err
		}
		return realMgmRegisterClient{GrpcClient: c}, nil
	}
)

// StartOAuthSession initiates a NetBird Device Code or PKCE OAuth session and returns
// the authorization URL immediately without blocking for browser completion.
func StartOAuthSession(ctx context.Context, managementURL, existingPrivateKey string) (*OAuthStartResult, error) {
	host, tlsEnabled, err := parseManagementURL(managementURL)
	if err != nil {
		return nil, err
	}
	normalizedMgmtURL := "https://" + host
	if !tlsEnabled {
		normalizedMgmtURL = "http://" + host
	}
	if strings.TrimSpace(managementURL) != "" {
		normalizedMgmtURL = strings.TrimSpace(managementURL)
	}

	var key wgtypes.Key
	if strings.TrimSpace(existingPrivateKey) != "" {
		key, err = wgtypes.ParseKey(strings.TrimSpace(existingPrivateKey))
	}
	if strings.TrimSpace(existingPrivateKey) == "" || err != nil {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate wireguard key: %w", err)
		}
	}

	mgmClient, err := mgm.NewClient(ctx, host, key, tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("connect management server %s: %w", host, err)
	}
	defer mgmClient.Close()

	deviceFlow, deviceErr := mgmClient.GetDeviceAuthorizationFlow()
	if deviceErr == nil && deviceFlow != nil && deviceFlow.GetProviderConfig() != nil {
		p := deviceFlow.GetProviderConfig()
		return startDeviceOAuthSession(ctx, normalizedMgmtURL, host, tlsEnabled, key, deviceAuthConfig{
			ClientID:           p.GetClientID(),
			ClientSecret:       p.GetClientSecret(), //nolint:staticcheck
			Audience:           p.GetAudience(),
			TokenEndpoint:      p.GetTokenEndpoint(),
			DeviceAuthEndpoint: p.GetDeviceAuthEndpoint(),
			Scope:              p.GetScope(),
			UseIDToken:         p.GetUseIDToken(),
		}, nil)
	}

	if deviceErr != nil {
		if s, ok := status.FromError(deviceErr); ok && s.Code() != codes.NotFound && s.Code() != codes.Unimplemented {
			return nil, fmt.Errorf("get device authorization flow: %w", deviceErr)
		}
	}

	pkceFlow, pkceErr := mgmClient.GetPKCEAuthorizationFlow(false)
	if pkceErr != nil {
		if deviceErr != nil {
			return nil, fmt.Errorf("get oauth flow (device: %v; pkce: %w)", deviceErr, pkceErr)
		}
		return nil, fmt.Errorf("get pkce authorization flow: %w", pkceErr)
	}
	if pkceFlow == nil || pkceFlow.GetProviderConfig() == nil {
		return nil, errors.New("management server returned empty PKCE authorization flow config")
	}

	p := pkceFlow.GetProviderConfig()
	return startPKCEOAuthSession(normalizedMgmtURL, host, tlsEnabled, key, pkceAuthConfig{
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
}

func startDeviceOAuthSession(
	ctx context.Context,
	managementURL, host string,
	tlsEnabled bool,
	key wgtypes.Key,
	cfg deviceAuthConfig,
	httpClient *http.Client,
) (*OAuthStartResult, error) {
	if cfg.ClientID == "" || cfg.DeviceAuthEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, errors.New("incomplete device authorization flow config from management server")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
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
		return nil, fmt.Errorf("create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	body, readErr := io.ReadAll(res.Body)
	res.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read device code response: %w", readErr)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (%d): %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var codeResp deviceCodeResponse
	if err := json.Unmarshal(body, &codeResp); err != nil {
		return nil, fmt.Errorf("parse device code response: %w", err)
	}
	if codeResp.Error != "" {
		return nil, fmt.Errorf("device code error %s: %s", codeResp.Error, codeResp.ErrorDescription)
	}
	if codeResp.DeviceCode == "" {
		return nil, errors.New("device code response missing device_code")
	}

	verifyURL := codeResp.VerificationURIComplete
	if verifyURL == "" {
		verifyURL = codeResp.VerificationURI
	}
	if verifyURL == "" {
		return nil, errors.New("device code response missing verification URI")
	}

	expiresIn := codeResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int(defaultOAuthTimeout.Seconds())
	}
	interval := time.Duration(codeResp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	sessCtx, cancel := context.WithTimeout(context.Background(), time.Duration(expiresIn)*time.Second)
	sessionID := uuid.NewString()
	sess := &oauthSession{
		id:            sessionID,
		managementURL: managementURL,
		host:          host,
		tlsEnabled:    tlsEnabled,
		key:           key,
		flowType:      "device",
		cancel:        cancel,
		waitToken: func(waitCtx context.Context) (string, error) {
			ctx, stop := mergeContexts(sessCtx, waitCtx)
			defer stop()

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				case <-ticker.C:
					tokResp, err := pollDeviceToken(ctx, httpClient, cfg, codeResp.DeviceCode)
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

					token := tokResp.AccessToken
					if cfg.UseIDToken && tokResp.IDToken != "" {
						token = tokResp.IDToken
					}
					if token == "" {
						return "", errors.New("device flow returned empty token")
					}
					return token, nil
				}
			}
		},
	}

	oauthSessionsMu.Lock()
	oauthSessions[sessionID] = sess
	oauthSessionsMu.Unlock()

	return &OAuthStartResult{
		SessionID: sessionID,
		AuthURL:   verifyURL,
		UserCode:  codeResp.UserCode,
		FlowType:  "device",
		ExpiresIn: expiresIn,
	}, nil
}

func startPKCEOAuthSession(
	managementURL, host string,
	tlsEnabled bool,
	key wgtypes.Key,
	cfg pkceAuthConfig,
) (*OAuthStartResult, error) {
	if cfg.ClientID == "" || cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || len(cfg.RedirectURLs) == 0 {
		return nil, errors.New("incomplete PKCE authorization flow config from management server")
	}

	ln, redirectURL, err := bindPKCERedirectListener(cfg.RedirectURLs)
	if err != nil {
		return nil, err
	}

	state, err := randomHexBytes(24)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate PKCE state: %w", err)
	}
	codeVerifier, err := randomBase64URLBytes(64)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}
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

	authURL := oauthCfg.AuthCodeURL(state, params...)
	tokenCh := make(chan *oauth2.Token, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
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

		tok, exchangeErr := oauthCfg.Exchange(req.Context(), code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
		if exchangeErr != nil {
			writePKCEResponse(w, http.StatusBadGateway, "NetBird token exchange failed: "+exchangeErr.Error())
			select {
			case errCh <- fmt.Errorf("PKCE token exchange: %w", exchangeErr):
			default:
			}
			return
		}

		writePKCEResponse(w, http.StatusOK, "NetBird login successful. You can close this window.")
		select {
		case tokenCh <- tok:
		default:
		}
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

	expiresIn := int(defaultOAuthTimeout.Seconds())
	sessCtx, cancel := context.WithTimeout(context.Background(), defaultOAuthTimeout)
	cleanup := func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(shutdownCtx)
		shutdownCancel()
		_ = ln.Close()
	}

	sessionID := uuid.NewString()
	sess := &oauthSession{
		id:            sessionID,
		managementURL: managementURL,
		host:          host,
		tlsEnabled:    tlsEnabled,
		key:           key,
		flowType:      "pkce",
		cancel:        cancel,
		cleanup:       cleanup,
		waitToken: func(waitCtx context.Context) (string, error) {
			ctx, stop := mergeContexts(sessCtx, waitCtx)
			defer stop()

			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case err := <-errCh:
				return "", err
			case tok := <-tokenCh:
				if cfg.UseIDToken {
					if idTok, ok := tok.Extra("id_token").(string); ok && idTok != "" {
						return idTok, nil
					}
				}
				if tok.AccessToken == "" {
					return "", errors.New("PKCE flow returned empty token")
				}
				return tok.AccessToken, nil
			}
		},
	}

	oauthSessionsMu.Lock()
	oauthSessions[sessionID] = sess
	oauthSessionsMu.Unlock()

	return &OAuthStartResult{
		SessionID: sessionID,
		AuthURL:   authURL,
		FlowType:  "pkce",
		ExpiresIn: expiresIn,
	}, nil
}

// CompleteOAuthSession waits for browser authorization on the given session, registers the
// peer with the NetBird management server, and returns the registered PrivateKey and metadata.
func CompleteOAuthSession(ctx context.Context, sessionID, deviceName string) (*OAuthCompleteResult, error) {
	oauthSessionsMu.Lock()
	sess := oauthSessions[sessionID]
	oauthSessionsMu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("oauth session %q not found", sessionID)
	}
	defer CancelOAuthSession(sessionID)

	jwtToken, err := sess.waitToken(ctx)
	if err != nil {
		return nil, err
	}

	privSSH, err := ssh.GeneratePrivateKey(ssh.ED25519)
	if err != nil {
		return nil, fmt.Errorf("generate SSH key: %w", err)
	}
	pubSSH, err := ssh.GeneratePublicKey(privSSH)
	if err != nil {
		return nil, fmt.Errorf("generate SSH public key: %w", err)
	}

	// nolint:staticcheck
	infoCtx := context.WithValue(ctx, system.DeviceNameCtxKey, deviceName)
	sysInfo := system.GetInfo(infoCtx)

	regClient, err := newMgmRegClient(ctx, sess.host, sess.key, sess.tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("connect management server for peer registration: %w", err)
	}
	defer regClient.Close()

	peerIP, fqdn, err := regClient.Register(uuid.Nil.String(), jwtToken, sysInfo, pubSSH)
	if err != nil {
		return nil, fmt.Errorf("register peer with management server: %w", err)
	}

	return &OAuthCompleteResult{
		PrivateKey:    sess.key.String(),
		PublicKey:     sess.key.PublicKey().String(),
		PeerIP:        peerIP,
		FQDN:          fqdn,
		ManagementURL: sess.managementURL,
	}, nil
}

// CancelOAuthSession cancels and removes an in-flight interactive OAuth session.
func CancelOAuthSession(sessionID string) {
	oauthSessionsMu.Lock()
	sess := oauthSessions[sessionID]
	if sess != nil {
		delete(oauthSessions, sessionID)
	}
	oauthSessionsMu.Unlock()

	if sess == nil {
		return
	}
	if sess.cancel != nil {
		sess.cancel()
	}
	if sess.cleanup != nil {
		sess.cleanup()
	}
}

func mergeContexts(a, b context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(a)
	stop := context.AfterFunc(b, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
