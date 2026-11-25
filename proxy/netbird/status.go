package netbird

import (
	"expvar"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/embed"
)

// StatusDetail holds live runtime status extracted from an embedded NetBird client.
type StatusDetail struct {
	ManagementConnected   bool                  `json:"managementConnected"`
	SignalConnected       bool                  `json:"signalConnected"`
	LocalIP               string                `json:"localIp,omitempty"`
	LocalIPv6             string                `json:"localIpv6,omitempty"`
	FQDN                  string                `json:"fqdn,omitempty"`
	PubKey                string                `json:"pubKey,omitempty"`
	LazyConnectionEnabled bool                  `json:"lazyConnectionEnabled"`
	PeersTotal            int                   `json:"peersTotal"`
	PeersConnected        int                   `json:"peersConnected"`
	Relays                []RelayStatusSnapshot `json:"relays,omitempty"`
	Peers                 []PeerStatusSnapshot  `json:"peers,omitempty"`
	Routes                []string              `json:"routes,omitempty"`
}

// RelayStatusSnapshot represents a NetBird relay server status.
type RelayStatusSnapshot struct {
	URI       string `json:"uri"`
	Available bool   `json:"available"`
	Transport string `json:"transport,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PeerStatusSnapshot represents a remote NetBird peer status.
type PeerStatusSnapshot struct {
	IP                 string   `json:"ip,omitempty"`
	IPv6               string   `json:"ipv6,omitempty"`
	FQDN               string   `json:"fqdn,omitempty"`
	PubKey             string   `json:"pubKey,omitempty"`
	Status             string   `json:"status"`
	Relayed            bool     `json:"relayed"`
	RelayServerAddress string   `json:"relayServerAddress,omitempty"`
	LatencyMs          int64    `json:"latencyMs,omitempty"`
	BytesTx            int64    `json:"bytesTx,omitempty"`
	BytesRx            int64    `json:"bytesRx,omitempty"`
	Routes             []string `json:"routes,omitempty"`
}

// StatusSnapshot is the JSON payload published under /debug/vars["netbird"][tag].
type StatusSnapshot struct {
	Tag                   string                `json:"tag"`
	State                 string                `json:"state"`
	DeviceName            string                `json:"deviceName,omitempty"`
	ManagementURL         string                `json:"managementUrl,omitempty"`
	ManagementConnected   bool                  `json:"managementConnected"`
	SignalConnected       bool                  `json:"signalConnected"`
	LocalIP               string                `json:"localIp,omitempty"`
	LocalIPv6             string                `json:"localIpv6,omitempty"`
	FQDN                  string                `json:"fqdn,omitempty"`
	PubKey                string                `json:"pubKey,omitempty"`
	LazyConnectionEnabled bool                  `json:"lazyConnectionEnabled"`
	PeersTotal            int                   `json:"peersTotal"`
	PeersConnected        int                   `json:"peersConnected"`
	Relays                []RelayStatusSnapshot `json:"relays,omitempty"`
	Peers                 []PeerStatusSnapshot  `json:"peers,omitempty"`
	Routes                []string              `json:"routes,omitempty"`
	LoginExpired          bool                  `json:"loginExpired"`
	LastError             string                `json:"lastError,omitempty"`
}

type embedClientAdapter struct {
	*embed.Client
}

func (a embedClientAdapter) StatusSnapshot() (*StatusDetail, error) {
	full, err := a.Client.Status()
	if err != nil {
		return nil, err
	}

	detail := &StatusDetail{
		ManagementConnected:   full.ManagementState.Connected,
		SignalConnected:       full.SignalState.Connected,
		LocalIP:               full.LocalPeerState.IP,
		LocalIPv6:             full.LocalPeerState.IPv6,
		FQDN:                  full.LocalPeerState.FQDN,
		PubKey:                full.LocalPeerState.PubKey,
		LazyConnectionEnabled: full.LazyConnectionEnabled,
		PeersTotal:            len(full.Peers),
	}

	routeSet := make(map[string]struct{})
	for r := range full.LocalPeerState.Routes {
		routeSet[r] = struct{}{}
	}

	if len(full.Relays) > 0 {
		detail.Relays = make([]RelayStatusSnapshot, 0, len(full.Relays))
		for _, r := range full.Relays {
			rs := RelayStatusSnapshot{
				URI:       r.URI,
				Available: r.Err == nil,
				Transport: r.Transport,
			}
			if r.Err != nil {
				rs.Error = r.Err.Error()
			}
			detail.Relays = append(detail.Relays, rs)
		}
	}

	if len(full.Peers) > 0 {
		detail.Peers = make([]PeerStatusSnapshot, 0, len(full.Peers))
		for i := range full.Peers {
			p := &full.Peers[i]
			if p.ConnStatus == embed.PeerStatusConnected {
				detail.PeersConnected++
			}
			var peerRoutes []string
			for r := range p.GetRoutes() {
				peerRoutes = append(peerRoutes, r)
				routeSet[r] = struct{}{}
			}
			sort.Strings(peerRoutes)

			detail.Peers = append(detail.Peers, PeerStatusSnapshot{
				IP:                 p.IP,
				IPv6:               p.IPv6,
				FQDN:               p.FQDN,
				PubKey:             p.PubKey,
				Status:             p.ConnStatus.String(),
				Relayed:            p.Relayed,
				RelayServerAddress: p.RelayServerAddress,
				LatencyMs:          p.Latency.Milliseconds(),
				BytesTx:            p.BytesTx,
				BytesRx:            p.BytesRx,
				Routes:             peerRoutes,
			})
		}
		sort.Slice(detail.Peers, func(i, j int) bool {
			if detail.Peers[i].FQDN != detail.Peers[j].FQDN {
				return detail.Peers[i].FQDN < detail.Peers[j].FQDN
			}
			return detail.Peers[i].IP < detail.Peers[j].IP
		})
	}

	if len(routeSet) > 0 {
		detail.Routes = make([]string, 0, len(routeSet))
		for r := range routeSet {
			detail.Routes = append(detail.Routes, r)
		}
		sort.Strings(detail.Routes)
	}

	return detail, nil
}

var (
	activeHandlersMu sync.RWMutex
	activeHandlers   = make(map[string]*Handler)
)

func init() {
	expvar.Publish("netbird", expvar.Func(activeNetBirdStatus))
}

func activeNetBirdStatus() any {
	activeHandlersMu.RLock()
	handlers := make([]*Handler, 0, len(activeHandlers))
	for _, h := range activeHandlers {
		handlers = append(handlers, h)
	}
	activeHandlersMu.RUnlock()

	result := make(map[string]StatusSnapshot, len(handlers))
	for _, h := range handlers {
		snap := h.StatusSnapshot()
		result[snap.Tag] = snap
	}
	return result
}

func (h *Handler) registerHandler(tag string) {
	base := strings.TrimSpace(tag)
	if base == "" {
		base = "netbird"
	}

	activeHandlersMu.Lock()
	defer activeHandlersMu.Unlock()

	key := base
	for i := 2; activeHandlers[key] != nil; i++ {
		key = fmt.Sprintf("%s-%d", base, i)
	}
	h.registryKey = key
	activeHandlers[key] = h
}

func (h *Handler) unregisterHandler() {
	if h.registryKey == "" {
		return
	}
	activeHandlersMu.Lock()
	defer activeHandlersMu.Unlock()
	if activeHandlers[h.registryKey] == h {
		delete(activeHandlers, h.registryKey)
	}
}

func (s clientState) String() string {
	switch s {
	case stateIdle:
		return "idle"
	case stateStarting:
		return "starting"
	case stateStarted:
		return "started"
	case stateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

func isLoginExpiredErr(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "peer login has expired") ||
		strings.Contains(lower, "login required") ||
		strings.Contains(lower, "permissiondenied")
}

// StatusSnapshot returns the current NetBird connection snapshot for this handler.
func (h *Handler) StatusSnapshot() StatusSnapshot {
	h.mu.Lock()
	snap := StatusSnapshot{
		Tag:           h.registryKey,
		State:         h.state.String(),
		DeviceName:    h.baseOpts.DeviceName,
		ManagementURL: h.managementURL,
		LoginExpired:  isLoginExpiredErr(h.lastStartErr),
	}
	if snap.Tag == "" {
		snap.Tag = "netbird"
	}
	if h.lastStartErr != nil {
		snap.LastError = h.lastStartErr.Error()
	}
	client := h.client
	started := h.state == stateStarted
	h.mu.Unlock()

	if started && client != nil {
		if detail, err := client.StatusSnapshot(); err == nil && detail != nil {
			snap.ManagementConnected = detail.ManagementConnected
			snap.SignalConnected = detail.SignalConnected
			snap.LocalIP = detail.LocalIP
			snap.LocalIPv6 = detail.LocalIPv6
			snap.FQDN = detail.FQDN
			snap.PubKey = detail.PubKey
			snap.LazyConnectionEnabled = detail.LazyConnectionEnabled
			snap.PeersTotal = detail.PeersTotal
			snap.PeersConnected = detail.PeersConnected
			snap.Relays = detail.Relays
			snap.Peers = detail.Peers
			snap.Routes = detail.Routes
		} else if err != nil && snap.LastError == "" {
			snap.LastError = err.Error()
		}
	}

	return snap
}
