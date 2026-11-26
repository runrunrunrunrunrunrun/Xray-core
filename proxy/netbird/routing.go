package netbird

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

const (
	routeRefreshInterval = 2 * time.Second
	dynamicLookupTimeout = 5 * time.Second
)

var defaultOverlayPrefix = netip.MustParsePrefix("100.64.0.0/10")

type routeSnapshot struct {
	overlayPrefixes  []netip.Prefix
	clientPrefixes   []netip.Prefix
	exitNodeV4       bool
	exitNodeV6       bool
	exitNodeIDs      []string
	selectedExitNode string
	routeExact       map[string]struct{}
	routeWildcard    []string
	dnsExact          map[string]struct{}
	dnsWildcard       []string
	dnsSubdomainBases []string
	dnsDomains        []string
	peerFQDNs         map[string]struct{}
	allRoutes         []string
}

func normalizeRoutingDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func addDomainPattern(exact map[string]struct{}, wildcard *[]string, pattern string) {
	norm := normalizeRoutingDomain(pattern)
	if norm == "" || norm == "." {
		return
	}
	if strings.HasPrefix(norm, "*.") {
		suffix := norm[1:] // ".corp.internal"
		if suffix != "." && !slices.Contains(*wildcard, suffix) {
			*wildcard = append(*wildcard, suffix)
		}
		return
	}
	exact[norm] = struct{}{}
}

func matchDomainPattern(exact map[string]struct{}, wildcard []string, subdomainSuffix []string, domain string) bool {
	if domain == "" {
		return false
	}
	if _, ok := exact[domain]; ok {
		return true
	}
	for _, suf := range wildcard {
		if strings.HasSuffix(domain, suf) {
			return true
		}
	}
	for _, base := range subdomainSuffix {
		if domain == base || strings.HasSuffix(domain, "."+base) {
			return true
		}
	}
	return false
}

func (s *routeSnapshot) matchRouteDomain(domain string) bool {
	if s == nil {
		return false
	}
	norm := normalizeRoutingDomain(domain)
	return matchDomainPattern(s.routeExact, s.routeWildcard, nil, norm)
}

func (s *routeSnapshot) matchDomain(domain string) bool {
	if s == nil {
		return false
	}
	norm := normalizeRoutingDomain(domain)
	if norm == "" {
		return false
	}
	if _, ok := s.peerFQDNs[norm]; ok {
		return true
	}
	if matchDomainPattern(s.routeExact, s.routeWildcard, nil, norm) {
		return true
	}
	// DNS patterns from NetBird ManagedDomains() can be non-wildcard apex zones
	// that still match subdomains (local resolver / NS groups have MatchSubdomains=true).
	return matchDomainPattern(s.dnsExact, s.dnsWildcard, s.dnsSubdomainBases, norm)
}

func (h *Handler) seedDefaultOverlay() {
	h.routeSnap.Store(&routeSnapshot{
		overlayPrefixes: []netip.Prefix{defaultOverlayPrefix},
		allRoutes:       []string{defaultOverlayPrefix.String()},
	})
}

func (h *Handler) registerRoutingHooks() {
	key := h.handlerKey()
	dns.RegisterDynamicResolver(key, h)
	routing.RegisterNetBirdRouteMatcher(key, h)
}

func (h *Handler) unregisterRoutingHooks() {
	key := h.handlerKey()
	dns.UnregisterDynamicResolver(key)
	routing.UnregisterNetBirdRouteMatcher(key)
}

func (h *Handler) handlerKey() string {
	if h.registryKey != "" {
		return h.registryKey
	}
	return "netbird"
}

func (h *Handler) startRouteRefreshLocked() {
	if h.routeRefreshCancel != nil || h.state == stateClosed {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.routeRefreshCancel = cancel

	go func() {
		ticker := time.NewTicker(routeRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				client := h.getClient()
				if client != nil {
					h.refreshRouteSnapshotFromClient(client)
				}
			}
		}
	}()
}

func (h *Handler) refreshRouteSnapshotFromClient(client netbirdClient) {
	if client == nil {
		return
	}
	table, err := client.RoutingTable()
	if err != nil {
		return
	}

	h.extraPrefixesMu.Lock()
	extras := slices.Clone(h.extraPrefixes)
	h.extraPrefixesMu.Unlock()

	overlay := table.OverlayPrefixes
	if len(overlay) == 0 {
		overlay = []netip.Prefix{defaultOverlayPrefix}
	}

	prefixSet := make(map[netip.Prefix]struct{}, len(table.ClientPrefixes)+len(extras))
	clientPrefixes := make([]netip.Prefix, 0, len(table.ClientPrefixes)+len(extras))
	addPrefix := func(p netip.Prefix) {
		if !p.IsValid() {
			return
		}
		if _, exists := prefixSet[p]; exists {
			return
		}
		prefixSet[p] = struct{}{}
		clientPrefixes = append(clientPrefixes, p)
	}
	for _, p := range table.ClientPrefixes {
		addPrefix(p)
	}
	for _, p := range extras {
		addPrefix(p)
	}

	routeExact := make(map[string]struct{})
	var routeWildcard []string
	for _, d := range table.RouteDomains {
		addDomainPattern(routeExact, &routeWildcard, d)
	}

	dnsExact := make(map[string]struct{})
	var dnsWildcard []string
	var dnsDomains []string
	for _, d := range table.DNSDomains {
		norm := normalizeRoutingDomain(d)
		if norm == "" {
			continue
		}
		dnsDomains = append(dnsDomains, norm)
		addDomainPattern(dnsExact, &dnsWildcard, norm)
	}

	peerFQDNs := make(map[string]struct{}, len(table.PeerFQDNs))
	for _, fqdn := range table.PeerFQDNs {
		norm := normalizeRoutingDomain(fqdn)
		if norm != "" {
			peerFQDNs[norm] = struct{}{}
		}
	}

	routeStrSet := make(map[string]struct{})
	var allRoutes []string
	addRouteStr := func(s string) {
		if s == "" {
			return
		}
		if _, ok := routeStrSet[s]; ok {
			return
		}
		routeStrSet[s] = struct{}{}
		allRoutes = append(allRoutes, s)
	}
	for _, p := range overlay {
		addRouteStr(p.String())
	}
	for _, p := range clientPrefixes {
		addRouteStr(p.String())
	}
	for _, d := range table.RouteDomains {
		addRouteStr(normalizeRoutingDomain(d))
	}
	slices.Sort(allRoutes)
	slices.Sort(dnsDomains)

	dnsSubdomainBases := make([]string, 0, len(dnsExact))
	for k := range dnsExact {
		dnsSubdomainBases = append(dnsSubdomainBases, k)
	}
	slices.Sort(dnsSubdomainBases)

	h.routeSnap.Store(&routeSnapshot{
		overlayPrefixes:   overlay,
		clientPrefixes:    clientPrefixes,
		exitNodeV4:        table.ExitNodeV4 && h.enableExitNode,
		exitNodeV6:        table.ExitNodeV6 && h.enableExitNode,
		exitNodeIDs:       slices.Clone(table.ExitNodeIDs),
		selectedExitNode:  table.SelectedExitNode,
		routeExact:        routeExact,
		routeWildcard:     routeWildcard,
		dnsExact:          dnsExact,
		dnsWildcard:       dnsWildcard,
		dnsSubdomainBases: dnsSubdomainBases,
		dnsDomains:        dnsDomains,
		peerFQDNs:         peerFQDNs,
		allRoutes:         allRoutes,
	})
}

func (h *Handler) recordDynamicRouteAddrs(addrs []netip.Addr) {
	if len(addrs) == 0 {
		return
	}
	h.extraPrefixesMu.Lock()
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		unmapped := addr.Unmap()
		prefix := netip.PrefixFrom(unmapped, unmapped.BitLen())
		if !slices.Contains(h.extraPrefixes, prefix) {
			h.extraPrefixes = append(h.extraPrefixes, prefix)
		}
	}
	h.extraPrefixesMu.Unlock()
}

// MatchDomain implements features/dns.DynamicResolver.
func (h *Handler) MatchDomain(domain string) bool {
	norm := normalizeRoutingDomain(domain)
	if norm == "" {
		return false
	}
	if client := h.getClient(); client != nil && client.MatchDNSDomain(norm) {
		return true
	}
	return h.routeSnap.Load().matchDomain(norm)
}

// LookupIP implements features/dns.DynamicResolver.
func (h *Handler) LookupIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	client := h.getClient()
	if client == nil {
		return nil, 0, dns.ErrEmptyResponse
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dynamicLookupTimeout)
	defer cancel()

	addrs, ttl, err := client.LookupIP(lookupCtx, domain, option.IPv4Enable, option.IPv6Enable)
	if err != nil {
		return nil, 0, err
	}
	if len(addrs) > 0 && h.routeSnap.Load().matchRouteDomain(domain) {
		h.recordDynamicRouteAddrs(addrs)
	}
	h.refreshRouteSnapshotFromClient(client)
	if len(addrs) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		unmapped := addr.Unmap()
		if unmapped.Is4() {
			b := unmapped.As4()
			ips = append(ips, net.IP(b[:]))
		} else if unmapped.Is6() {
			b := unmapped.As16()
			ips = append(ips, net.IP(b[:]))
		}
	}
	if ttl == 0 {
		ttl = 60
	}
	return ips, ttl, nil
}

// MatchTarget implements features/routing.NetBirdRouteMatcher.
func (h *Handler) MatchTarget(domain string, ips []net.IP, mode routing.NetBirdRouteMode) bool {
	snap := h.routeSnap.Load()
	switch mode {
	case routing.NetBirdRouteModeExit:
		if !h.enableExitNode || snap == nil || (!snap.exitNodeV4 && !snap.exitNodeV6) {
			return false
		}
		if len(ips) == 0 {
			return true
		}
		for _, rawIP := range ips {
			addr, ok := netip.AddrFromSlice(rawIP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() && snap.exitNodeV4 {
				return true
			}
			if addr.Is6() && snap.exitNodeV6 {
				return true
			}
		}
		return false

	case routing.NetBirdRouteModeRoutes:
		if domain != "" {
			if snap.matchDomain(domain) {
				return true
			}
			if client := h.getClient(); client != nil && client.MatchDNSDomain(domain) {
				return true
			}
		}
		if len(ips) > 0 && snap != nil {
			for _, rawIP := range ips {
				addr, ok := netip.AddrFromSlice(rawIP)
				if !ok {
					continue
				}
				addr = addr.Unmap()
				for _, p := range snap.overlayPrefixes {
					if p.Contains(addr) {
						return true
					}
				}
				for _, p := range snap.clientPrefixes {
					if p.Contains(addr) {
						return true
					}
				}
			}
		}
		return false

	default:
		return false
	}
}
