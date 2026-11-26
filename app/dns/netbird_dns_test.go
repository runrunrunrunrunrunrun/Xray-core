package dns_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/dns/fakedns"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/proxy/freedom"
)

type stubDynamicResolver struct {
	matchFn  func(domain string) bool
	lookupFn func(ctx context.Context, domain string, option feature_dns.IPOption) ([]net.IP, uint32, error)
}

func (s stubDynamicResolver) MatchDomain(domain string) bool {
	return s.matchFn(domain)
}

func (s stubDynamicResolver) LookupIP(ctx context.Context, domain string, option feature_dns.IPOption) ([]net.IP, uint32, error) {
	return s.lookupFn(ctx, domain, option)
}

func TestDynamicResolverTakesPrecedenceAndReturnsNoData(t *testing.T) {
	const resolverID = "nb-dns-test"
	feature_dns.RegisterDynamicResolver(resolverID, stubDynamicResolver{
		matchFn: func(domain string) bool {
			return domain == "peer.netbird.selfhosted" || domain == "nodata.netbird.selfhosted"
		},
		lookupFn: func(_ context.Context, domain string, option feature_dns.IPOption) ([]net.IP, uint32, error) {
			if domain == "peer.netbird.selfhosted" && option.IPv4Enable {
				return []net.IP{net.ParseAddress("100.64.0.22").IP()}, 120, nil
			}
			return nil, 0, nil
		},
	})
	defer feature_dns.UnregisterDynamicResolver(resolverID)

	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&fakedns.FakeDnsPool{
				IpPool:  "198.18.0.0/15",
				LruSize: 64,
			}),
			serial.ToTypedMessage(&Config{
				QueryStrategy: QueryStrategy_USE_IP,
				NameServer: []*NameServer{
					{
						Address: &net.Endpoint{
							Address: &net.IPOrDomain{Address: &net.IPOrDomain_Domain{Domain: "fakedns"}},
						},
					},
				},
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	})
	common.Must(err)
	common.Must(v.Start())
	defer v.Close()

	d := v.GetFeature(feature_dns.ClientType()).(feature_dns.Client)

	// Unmatched domain still gets FakeDNS IP when FakeEnable is true.
	fakeIPs, _, err := d.LookupIP("public.example.com", feature_dns.IPOption{
		IPv4Enable: true,
		FakeEnable: true,
	})
	if err != nil || len(fakeIPs) == 0 || fakeIPs[0][0] != 198 {
		t.Fatalf("expected FakeDNS IP for public domain, got ips=%v err=%v", fakeIPs, err)
	}

	// NetBird-managed domain bypasses FakeDNS and returns real overlay IP.
	ips, ttl, err := d.LookupIP("PEER.netbird.selfhosted.", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: true,
	})
	if err != nil || ttl != 120 || len(ips) != 1 || ips[0].String() != "100.64.0.22" {
		t.Fatalf("unexpected dynamic LookupIP result: ips=%v ttl=%d err=%v", ips, ttl, err)
	}

	// NetBird-managed domain with no AAAA record returns ErrEmptyResponse instead of FakeDNS IP.
	_, _, err = d.LookupIP("nodata.netbird.selfhosted", feature_dns.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
		FakeEnable: true,
	})
	if !stderrors.Is(err, feature_dns.ErrEmptyResponse) {
		t.Fatalf("expected ErrEmptyResponse on NODATA dynamic match, got %v", err)
	}
}
