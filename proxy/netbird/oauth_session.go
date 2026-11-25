package netbird

import (
	"context"
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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmcommon "github.com/netbirdio/netbird/shared/management/client/common"
)

// OAuthStartOptions configures interactive NetBird OAuth initialization.
type OAuthStartOptions struct {
	ManagementURL      string
	ExistingPrivateKey string
	ForceDeviceFlow    bool
	LoginHint          string
}

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

type oauthDiscoveryClient interface {
	Close() error
	GetPKCEAuthorizationFlow(sessionExtend bool) (pkceAuthConfig, error)
	GetDeviceAuthorizationFlow() (deviceAuthConfig, error)
}

type realMgmDiscoveryClient struct {
	*mgm.GrpcClient
}

func (c realMgmDiscoveryClient) GetPKCEAuthorizationFlow(sessionExtend bool) (pkceAuthConfig, error) {
	flow, err := c.GrpcClient.GetPKCEAuthorizationFlow(sessionExtend)
	if err != nil {
		return pkceAuthConfig{}, err
	}
	if flow == nil || flow.GetProviderConfig() == nil {
		return pkceAuthConfig{}, errors.New("management server returned empty PKCE authorization flow config")
	}
	p := flow.GetProviderConfig()
	return pkceAuthConfig{
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
	}, nil
}

func (c realMgmDiscoveryClient) GetDeviceAuthorizationFlow() (deviceAuthConfig, error) {
	flow, err := c.GrpcClient.GetDeviceAuthorizationFlow()
	if err != nil {
		return deviceAuthConfig{}, err
	}
	if flow == nil || flow.GetProviderConfig() == nil {
		return deviceAuthConfig{}, errors.New("management server returned empty device authorization flow config")
	}
	p := flow.GetProviderConfig()
	return deviceAuthConfig{
		ClientID:           p.GetClientID(),
		ClientSecret:       p.GetClientSecret(), //nolint:staticcheck
		Audience:           p.GetAudience(),
		TokenEndpoint:      p.GetTokenEndpoint(),
		DeviceAuthEndpoint: p.GetDeviceAuthEndpoint(),
		Scope:              p.GetScope(),
		UseIDToken:         p.GetUseIDToken(),
	}, nil
}

var (
	oauthSessionsMu       sync.Mutex
	oauthSessions         = make(map[string]*oauthSession)
	newMgmDiscoveryClient = func(ctx context.Context, host string, key wgtypes.Key, tlsEnabled bool) (oauthDiscoveryClient, error) {
		c, err := mgm.NewClient(ctx, host, key, tlsEnabled)
		if err != nil {
			return nil, err
		}
		return realMgmDiscoveryClient{GrpcClient: c}, nil
	}
	newMgmRegClient = func(ctx context.Context, host string, key wgtypes.Key, tlsEnabled bool) (mgmRegisterClient, error) {
		c, err := mgm.NewClient(ctx, host, key, tlsEnabled)
		if err != nil {
			return nil, err
		}
		return realMgmRegisterClient{GrpcClient: c}, nil
	}
)

// StartOAuthSession initiates a NetBird PKCE or Device Code OAuth session and returns
// the authorization URL immediately without blocking for browser completion.
func StartOAuthSession(ctx context.Context, managementURL, existingPrivateKey string) (*OAuthStartResult, error) {
	return StartOAuthSessionWithOptions(ctx, OAuthStartOptions{
		ManagementURL:      managementURL,
		ExistingPrivateKey: existingPrivateKey,
	})
}

// StartOAuthSessionWithOptions mirrors NetBird client/internal/auth/oauth.go:NewOAuthFlow:
// it tries PKCE Authorization Code Flow first (passing sessionExtend when reusing an
// existing peer key), falling back to Device Authorization Flow if PKCE fails or if
// ForceDeviceFlow is set.
func StartOAuthSessionWithOptions(ctx context.Context, opts OAuthStartOptions) (*OAuthStartResult, error) {
	host, tlsEnabled, err := parseManagementURL(opts.ManagementURL)
	if err != nil {
		return nil, err
	}
	normalizedMgmtURL := "https://" + host
	if !tlsEnabled {
		normalizedMgmtURL = "http://" + host
	}
	if strings.TrimSpace(opts.ManagementURL) != "" {
		normalizedMgmtURL = strings.TrimSpace(opts.ManagementURL)
	}

	trimmedExisting := strings.TrimSpace(opts.ExistingPrivateKey)
	sessionExtend := trimmedExisting != ""

	var key wgtypes.Key
	if sessionExtend {
		key, err = wgtypes.ParseKey(trimmedExisting)
	}
	if !sessionExtend || err != nil {
		sessionExtend = false
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate wireguard key: %w", err)
		}
	}

	mgmClient, err := newMgmDiscoveryClient(ctx, host, key, tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("connect management server %s: %w", host, err)
	}
	defer mgmClient.Close()

	var pkceErr error
	if !opts.ForceDeviceFlow {
		var pkceCfg pkceAuthConfig
		pkceCfg, pkceErr = mgmClient.GetPKCEAuthorizationFlow(sessionExtend)
		if pkceErr == nil {
			pkceCfg.LoginHint = strings.TrimSpace(opts.LoginHint)
			res, startErr := startPKCEOAuthSession(normalizedMgmtURL, host, tlsEnabled, key, pkceCfg)
			if startErr == nil {
				return res, nil
			}
			pkceErr = startErr
		}
	}

	deviceCfg, deviceErr := mgmClient.GetDeviceAuthorizationFlow()
	if deviceErr == nil {
		return startDeviceOAuthSession(ctx, normalizedMgmtURL, host, tlsEnabled, key, deviceCfg, nil)
	}

	switch s, ok := status.FromError(deviceErr); {
	case ok && s.Code() == codes.NotFound:
		return nil, fmt.Errorf("no SSO provider returned from management %s (pkce: %v)", normalizedMgmtURL, pkceErr)
	case ok && s.Code() == codes.Unimplemented:
		return nil, fmt.Errorf("the management server %s does not support SSO providers", normalizedMgmtURL)
	case pkceErr != nil:
		return nil, fmt.Errorf("get oauth flow (pkce: %v; device: %w)", pkceErr, deviceErr)
	default:
		return nil, fmt.Errorf("get device authorization flow: %w", deviceErr)
	}
}

func startDeviceOAuthSession(
	ctx context.Context,
	managementURL, host string,
	tlsEnabled bool,
	key wgtypes.Key,
	cfg deviceAuthConfig,
	httpClient *http.Client,
) (*OAuthStartResult, error) {
	if err := validateDeviceAuthConfig(cfg); err != nil {
		return nil, err
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

					return selectToken(tokResp.AccessToken, tokResp.IDToken, cfg.UseIDToken, cfg.Audience)
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
	if err := validatePKCEConfig(cfg); err != nil {
		return nil, err
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
	codeVerifier, err := randomHexBytes(32)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}

	oauthCfg, authURL := buildPKCEOAuthConfigAndURL(cfg, redirectURL, state, codeVerifier)
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
				return tok, nil
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

func isTransientMgmError(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Internal:
		return true
	default:
		return false
	}
}

func registerPeerWithRetry(ctx context.Context, sess *oauthSession, jwtToken string, sysInfo *system.Info, pubSSH []byte) (string, string, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * 500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", "", ctx.Err()
			case <-timer.C:
			}
		}

		regClient, err := newMgmRegClient(ctx, sess.host, sess.key, sess.tlsEnabled)
		if err != nil {
			lastErr = fmt.Errorf("connect management server for peer registration: %w", err)
			if isTransientMgmError(err) {
				continue
			}
			return "", "", lastErr
		}
		peerIP, fqdn, regErr := regClient.Register(uuid.Nil.String(), jwtToken, sysInfo, pubSSH)
		_ = regClient.Close()
		if regErr == nil {
			return peerIP, fqdn, nil
		}
		lastErr = fmt.Errorf("register peer with management server: %w", regErr)
		if !isTransientMgmError(regErr) {
			return "", "", lastErr
		}
	}
	return "", "", lastErr
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

	peerIP, fqdn, err := registerPeerWithRetry(ctx, sess, jwtToken, sysInfo, pubSSH)
	if err != nil {
		return nil, err
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
