package dns

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/net"
)

// DynamicResolver provides in-process DNS resolution for NetBird-managed
// domains without routing back through the system resolver or TUN.
type DynamicResolver interface {
	MatchDomain(domain string) bool
	LookupIP(ctx context.Context, domain string, option IPOption) ([]net.IP, uint32, error)
}

var (
	dynamicResolversMu sync.RWMutex
	dynamicResolvers   = make(map[string]DynamicResolver)
)

// RegisterDynamicResolver registers or replaces a dynamic resolver by key.
func RegisterDynamicResolver(id string, resolver DynamicResolver) {
	if id == "" || resolver == nil {
		return
	}
	dynamicResolversMu.Lock()
	dynamicResolvers[id] = resolver
	dynamicResolversMu.Unlock()
}

// UnregisterDynamicResolver removes a dynamic resolver registered under id.
func UnregisterDynamicResolver(id string) {
	if id == "" {
		return
	}
	dynamicResolversMu.Lock()
	delete(dynamicResolvers, id)
	dynamicResolversMu.Unlock()
}

// LookupDynamic checks registered dynamic resolvers for a matching domain.
// If any resolver claims ownership of domain, matched is true and fallback to
// normal DNS/FakeDNS servers must not occur.
func LookupDynamic(ctx context.Context, domain string, option IPOption) (ips []net.IP, ttl uint32, matched bool, err error) {
	norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if norm == "" {
		return nil, 0, false, nil
	}

	dynamicResolversMu.RLock()
	resolvers := make([]DynamicResolver, 0, len(dynamicResolvers))
	for _, r := range dynamicResolvers {
		resolvers = append(resolvers, r)
	}
	dynamicResolversMu.RUnlock()

	for _, r := range resolvers {
		if !r.MatchDomain(norm) {
			continue
		}
		matched = true
		ips, ttl, err = r.LookupIP(ctx, norm, option)
		if err != nil {
			return nil, 0, true, err
		}
		if len(ips) == 0 {
			return nil, 0, true, ErrEmptyResponse
		}
		return ips, ttl, true, nil
	}
	return nil, 0, false, nil
}
