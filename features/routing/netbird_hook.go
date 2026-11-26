package routing

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/net"
)

// NetBirdRouteMode selects which subset of dynamic NetBird routes a matcher tests.
type NetBirdRouteMode string

const (
	NetBirdRouteModeRoutes NetBirdRouteMode = "routes"
	NetBirdRouteModeExit   NetBirdRouteMode = "exit"
)

// NetBirdRouteMatcher matches routing targets against a NetBird handler's
// synced overlay networks, client routes, domains, and exit-node state.
type NetBirdRouteMatcher interface {
	MatchTarget(domain string, ips []net.IP, mode NetBirdRouteMode) bool
}

var (
	netbirdMatchersMu sync.RWMutex
	netbirdMatchers   = make(map[string]NetBirdRouteMatcher)
)

// RegisterNetBirdRouteMatcher registers or replaces a NetBird route matcher by tag.
func RegisterNetBirdRouteMatcher(tag string, matcher NetBirdRouteMatcher) {
	if tag == "" || matcher == nil {
		return
	}
	netbirdMatchersMu.Lock()
	netbirdMatchers[tag] = matcher
	netbirdMatchersMu.Unlock()
}

// UnregisterNetBirdRouteMatcher removes a registered NetBird route matcher.
func UnregisterNetBirdRouteMatcher(tag string) {
	if tag == "" {
		return
	}
	netbirdMatchersMu.Lock()
	delete(netbirdMatchers, tag)
	netbirdMatchersMu.Unlock()
}

// MatchNetBirdRoute reports whether (domain, ips) matches the NetBird route
// table for tag (or any registered NetBird handler when tag is empty).
func MatchNetBirdRoute(tag string, domain string, ips []net.IP, mode NetBirdRouteMode) bool {
	if mode != NetBirdRouteModeRoutes && mode != NetBirdRouteModeExit {
		return false
	}
	normDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")

	netbirdMatchersMu.RLock()
	if tag != "" {
		m := netbirdMatchers[tag]
		netbirdMatchersMu.RUnlock()
		if m == nil {
			return false
		}
		return m.MatchTarget(normDomain, ips, mode)
	}
	matchers := make([]NetBirdRouteMatcher, 0, len(netbirdMatchers))
	for _, m := range netbirdMatchers {
		matchers = append(matchers, m)
	}
	netbirdMatchersMu.RUnlock()

	for _, m := range matchers {
		if m.MatchTarget(normDomain, ips, mode) {
			return true
		}
	}
	return false
}
