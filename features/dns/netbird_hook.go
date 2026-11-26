package dns

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/net"
)

// ErrDynamicFallthrough indicates a dynamic resolver declined ownership for this
// query so lookup should fall through to normal DNS resolution.
var ErrDynamicFallthrough = errors.New("dynamic dns fallthrough")

// DynamicResolver provides in-process DNS resolution for NetBird-managed
// domains without routing back through the system resolver or TUN.
type DynamicResolver interface {
	MatchDomain(domain string) bool
	LookupIP(ctx context.Context, domain string, option IPOption) ([]net.IP, uint32, error)
}

// DynamicFallbackResolver handles fallback resolution when normal Xray DNS
// servers produce no answer (for example, NetBird primary "All domains" DNS).
type DynamicFallbackResolver interface {
	LookupFallbackIP(ctx context.Context, domain string, option IPOption) ([]net.IP, uint32, bool, error)
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

func snapshotDynamicResolvers() []DynamicResolver {
	dynamicResolversMu.RLock()
	defer dynamicResolversMu.RUnlock()
	resolvers := make([]DynamicResolver, 0, len(dynamicResolvers))
	for _, r := range dynamicResolvers {
		resolvers = append(resolvers, r)
	}
	return resolvers
}

// LookupDynamic checks registered dynamic resolvers for a matching domain.
// If any resolver claims ownership of domain, matched is true and fallback to
// normal DNS/FakeDNS servers must not occur.
func LookupDynamic(ctx context.Context, domain string, option IPOption) (ips []net.IP, ttl uint32, matched bool, err error) {
	norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if norm == "" {
		return nil, 0, false, nil
	}

	for _, r := range snapshotDynamicResolvers() {
		if !r.MatchDomain(norm) {
			continue
		}
		ips, ttl, err = r.LookupIP(ctx, norm, option)
		if errors.Is(err, ErrDynamicFallthrough) {
			continue
		}
		matched = true
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

// LookupDynamicFallback queries registered fallback resolvers after normal DNS returns no IPs.
func LookupDynamicFallback(ctx context.Context, domain string, option IPOption) (ips []net.IP, ttl uint32, matched bool, err error) {
	norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if norm == "" {
		return nil, 0, false, nil
	}

	for _, r := range snapshotDynamicResolvers() {
		fb, ok := r.(DynamicFallbackResolver)
		if !ok {
			continue
		}
		ips, ttl, ok, err = fb.LookupFallbackIP(ctx, norm, option)
		if !ok || errors.Is(err, ErrDynamicFallthrough) {
			continue
		}
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
