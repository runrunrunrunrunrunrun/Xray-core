package netbird

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

func TestHandlerStatusSnapshotAndExpvar(t *testing.T) {
	pm := newTestPolicyManager(t)

	client := &fakeNetbirdClient{
		statusSnapshotFn: func() (*StatusDetail, error) {
			return &StatusDetail{
				ManagementConnected:   true,
				SignalConnected:       true,
				LocalIP:               "100.77.220.113",
				FQDN:                  "onexray.net.loop",
				PubKey:                "pub-local",
				LazyConnectionEnabled: true,
				PeersTotal:            1,
				PeersConnected:        1,
				Relays: []RelayStatusSnapshot{
					{URI: "rels://relay.l0op.site:8443", Available: true, Transport: "quic"},
				},
				Peers: []PeerStatusSnapshot{
					{
						IP:        "100.77.0.10",
						FQDN:      "nas.net.loop",
						PubKey:    "pub-nas",
						Status:    "Connected",
						LatencyMs: 12,
						BytesTx:   1024,
						BytesRx:   2048,
						Routes:    []string{"10.113.0.0/16"},
					},
				},
				Routes: []string{"10.113.0.0/16"},
			}, nil
		},
	}

	h := newHandlerWithTag("nb-status-test", pm, client, time.Second, nil, nil, true)
	h.managementURL = "https://net.l0op.site"
	h.baseOpts.DeviceName = "onexray-device"

	if err := h.ensureStarted(context.Background()); err != nil {
		t.Fatalf("ensureStarted failed: %v", err)
	}

	raw := activeNetBirdStatus().(map[string]StatusSnapshot)
	snap, ok := raw["nb-status-test"]
	if !ok {
		t.Fatalf("expected nb-status-test in activeNetBirdStatus, got %+v", raw)
	}
	if snap.State != "started" || snap.LocalIP != "100.77.220.113" || snap.PeersConnected != 1 {
		t.Fatalf("unexpected status snapshot: %+v", snap)
	}
	if len(snap.Relays) != 1 || snap.Relays[0].Transport != "quic" {
		t.Fatalf("unexpected relays: %+v", snap.Relays)
	}

	_ = h.Close()
	rawAfter := activeNetBirdStatus().(map[string]StatusSnapshot)
	if _, exists := rawAfter["nb-status-test"]; exists {
		t.Fatal("expected handler to be unregistered after Close")
	}

	// Verify LoginExpired detection on expired peer error.
	hExp := newHandlerWithTag("nb-expired-test", pm, &fakeNetbirdClient{
		startFn: func(context.Context) error {
			return stderrors.New("login: rpc error: code = PermissionDenied desc = peer login has expired")
		},
	}, time.Second, nil, nil, true)
	defer hExp.Close()

	_ = hExp.ensureStarted(context.Background())
	expSnap := hExp.StatusSnapshot()
	if !expSnap.LoginExpired {
		t.Fatalf("expected LoginExpired=true, got %+v", expSnap)
	}

	// Verify SetupKey PermissionDenied preserves LastError without false LoginExpired.
	hSetupErr := newHandlerWithTag("nb-setup-err-test", pm, &fakeNetbirdClient{
		startFn: func(context.Context) error {
			return stderrors.New("login: rpc error: code = PermissionDenied desc = setup key is invalid or already used")
		},
	}, time.Second, nil, nil, false)
	hSetupErr.baseOpts.SetupKey = "test-setup-key"
	defer hSetupErr.Close()

	_ = hSetupErr.ensureStarted(context.Background())
	setupSnap := hSetupErr.StatusSnapshot()
	if setupSnap.LoginExpired {
		t.Fatalf("expected LoginExpired=false for SetupKey error, got %+v", setupSnap)
	}
	if setupSnap.LastError == "" {
		t.Fatal("expected LastError to be preserved for SetupKey error")
	}
}

func TestHandlerStatusSnapshotWhileStarting(t *testing.T) {
	pm := newTestPolicyManager(t)
	inStart := make(chan struct{})
	release := make(chan struct{})

	h := &Handler{
		policyManager:  pm,
		startupTimeout: 2 * time.Second,
		baseOpts:       embed.Options{SetupKey: "starting-key", DeviceName: "win-dev"},
		managementURL:  "https://net.l0op.site",
		newClientFn: func(opts embed.Options) (netbirdClient, error) {
			return &fakeNetbirdClient{
				startFn: func(ctx context.Context) error {
					close(inStart)
					<-release
					return nil
				},
				statusSnapshotFn: func() (*StatusDetail, error) {
					return &StatusDetail{
						ManagementConnected: true,
						SignalConnected:     false,
						SignalError:         "dial signal failed",
					}, nil
				},
			}, nil
		},
		state: stateIdle,
	}
	h.registerHandler("nb-starting-status")
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = h.Close()
	}()

	if err := h.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	<-inStart

	snap := h.StatusSnapshot()
	if snap.State != "starting" {
		t.Fatalf("State = %q, want starting", snap.State)
	}
	if !snap.ManagementConnected || snap.SignalConnected {
		t.Fatalf("unexpected control/signal flags while starting: %+v", snap)
	}
	if snap.LastError != "dial signal failed" {
		t.Fatalf("LastError = %q, want %q", snap.LastError, "dial signal failed")
	}

	close(release)
	if err := h.ensureStarted(context.Background()); err != nil {
		t.Fatalf("ensureStarted() failed: %v", err)
	}
}
