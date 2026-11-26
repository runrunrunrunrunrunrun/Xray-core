package netbird

import (
	"context"
	stderrors "errors"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

func TestConfigProtobufRoundTripWithExitNode(t *testing.T) {
	in := &Config{
		DeviceName:     "win-node",
		SetupKey:       "setup-key",
		ManagementUrl:  "https://net.l0op.site",
		EnableExitNode: true,
		StartupTimeout: 60,
	}
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}
	var out Config
	if err := proto.Unmarshal(raw, &out); err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}
	if !out.GetEnableExitNode() || out.GetManagementUrl() != in.ManagementUrl || out.GetStartupTimeout() != 60 {
		t.Fatalf("round-trip mismatch: %+v", &out)
	}
}

func TestHandlerRoutingMatcherAndDNSLookup(t *testing.T) {
	pm := newTestPolicyManager(t)

	client := &fakeNetbirdClient{
		routingTableFn: func() (embed.RoutingTable, error) {
			return embed.RoutingTable{
				OverlayPrefixes: []netip.Prefix{netip.MustParsePrefix("100.77.0.0/16")},
				ClientPrefixes: []netip.Prefix{
					netip.MustParsePrefix("10.113.0.0/16"),
					netip.MustParsePrefix("fd00:10::/64"),
				},
				ExitNodeV4:       true,
				ExitNodeV6:       false,
				ExitNodeIDs:      []string{"exit-sg"},
				SelectedExitNode: "exit-sg",
				RouteDomains:     []string{"*.corp.example", "exact.internal"},
				DNSDomains:       []string{"netbird.selfhosted", "*.ns.internal"},
				PeerFQDNs:        []string{"nas.netbird.selfhosted"},
			}, nil
		},
		matchDNSDomainFn: func(domain string) bool {
			return domain == "nas.netbird.selfhosted" ||
				domain == "api.corp.example" ||
				domain == "nodata.netbird.selfhosted"
		},
		lookupIPFn: func(_ context.Context, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
			switch domain {
			case "nas.netbird.selfhosted":
				if ipv4 {
					return []netip.Addr{netip.MustParseAddr("100.77.0.10")}, 90, nil
				}
				return nil, 0, nil
			case "api.corp.example":
				if ipv4 {
					return []netip.Addr{netip.MustParseAddr("172.30.1.5")}, 45, nil
				}
				return nil, 0, nil
			case "nodata.netbird.selfhosted":
				return nil, 0, nil
			default:
				return nil, 0, stderrors.New("not found")
			}
		},
	}

	h := newHandlerWithTag("nb-route-test", pm, client, time.Second, nil, nil, true)
	h.enableExitNode = true
	defer h.Close()

	if err := h.ensureStarted(context.Background()); err != nil {
		t.Fatalf("ensureStarted failed: %v", err)
	}

	// Verify routes matching (overlay IPs, client CIDRs, dynamic domains, FQDNs, DNS zones).
	if !routing.MatchNetBirdRoute("nb-route-test", "", []stdnet.IP{stdnet.ParseIP("100.77.0.10")}, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected overlay IP 100.77.0.10 to match")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "", []stdnet.IP{stdnet.ParseIP("10.113.5.9")}, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected client route IP 10.113.5.9 to match")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "", []stdnet.IP{stdnet.ParseIP("fd00:10::1")}, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected IPv6 client route fd00:10::1 to match")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "api.corp.example", nil, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected wildcard route domain to match")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "exact.internal", nil, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected exact route domain to match")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "nas.netbird.selfhosted", nil, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected peer FQDN to match")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "svc.ns.internal", nil, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected wildcard DNS domain to match")
	}
	if routing.MatchNetBirdRoute("nb-route-test", "google.com", []stdnet.IP{stdnet.ParseIP("8.8.8.8")}, routing.NetBirdRouteModeRoutes) {
		t.Fatal("did not expect public domain/IP to match NetBird routes")
	}

	// Verify Exit Node matching (v4 active, v6 inactive).
	if !routing.MatchNetBirdRoute("nb-route-test", "", []stdnet.IP{stdnet.ParseIP("8.8.8.8")}, routing.NetBirdRouteModeExit) {
		t.Fatal("expected public IPv4 to match active v4 Exit Node")
	}
	if routing.MatchNetBirdRoute("nb-route-test", "", []stdnet.IP{stdnet.ParseIP("2001:4860:4860::8888")}, routing.NetBirdRouteModeExit) {
		t.Fatal("did not expect IPv6 to match v4-only Exit Node")
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "example.com", nil, routing.NetBirdRouteModeExit) {
		t.Fatal("expected domain target to match active Exit Node")
	}

	// Verify LookupDynamic resolves peer FQDN and caches dynamic route IPs immediately.
	ips, ttl, matched, err := dns.LookupDynamic(context.Background(), "api.corp.example.", dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: true})
	if err != nil || !matched || ttl != 45 || len(ips) != 1 || ips[0].String() != "172.30.1.5" {
		t.Fatalf("unexpected LookupDynamic result: ips=%v ttl=%d matched=%v err=%v", ips, ttl, matched, err)
	}
	if !routing.MatchNetBirdRoute("nb-route-test", "", []stdnet.IP{stdnet.ParseIP("172.30.1.5")}, routing.NetBirdRouteModeRoutes) {
		t.Fatal("expected resolved dynamic route IP 172.30.1.5 to match immediately after DNS lookup")
	}

	// Managed domain with NODATA must return ErrEmptyResponse with matched=true so Xray doesn't leak to public DNS.
	_, _, matched, err = dns.LookupDynamic(context.Background(), "nodata.netbird.selfhosted", dns.IPOption{IPv6Enable: true})
	if !matched || !stderrors.Is(err, dns.ErrEmptyResponse) {
		t.Fatalf("expected matched=true and ErrEmptyResponse, got matched=%v err=%v", matched, err)
	}

	// Fallthrough & RCodeError mapping on dynamic resolver.
	client.matchDNSDomainFn = func(domain string) bool {
		return domain == "fall.example" || domain == "missing.netbird.selfhosted" || domain == "nas.netbird.selfhosted" || domain == "api.corp.example" || domain == "nodata.netbird.selfhosted"
	}
	origLookup := client.lookupIPFn
	client.lookupIPFn = func(ctx context.Context, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
		switch domain {
		case "fall.example":
			return nil, 0, embed.ErrDNSFallthrough
		case "missing.netbird.selfhosted":
			return nil, 0, &embed.DNSRcodeError{Domain: domain, Rcode: 3}
		default:
			return origLookup(ctx, domain, ipv4, ipv6)
		}
	}
	_, _, matched, err = dns.LookupDynamic(context.Background(), "fall.example", dns.IPOption{IPv4Enable: true})
	if matched || err != nil {
		t.Fatalf("expected matched=false and err=nil on fallthrough, got matched=%v err=%v", matched, err)
	}
	_, _, matched, err = dns.LookupDynamic(context.Background(), "missing.netbird.selfhosted", dns.IPOption{IPv4Enable: true})
	if !matched || dns.RCodeFromError(err) != 3 {
		t.Fatalf("expected matched=true and RCode=3, got matched=%v err=%v", matched, err)
	}

	// Disabled exit node must return false even if ExitNodeV4 is true in table.
	h.enableExitNode = false
	h.refreshRouteSnapshotFromClient(client)
	if routing.MatchNetBirdRoute("nb-route-test", "example.com", []stdnet.IP{stdnet.ParseIP("8.8.8.8")}, routing.NetBirdRouteModeExit) {
		t.Fatal("did not expect Exit Node to match when enableExitNode=false")
	}

	// StatusSnapshot reflects synced exit node & DNS fields.
	snap := h.StatusSnapshot()
	if !snap.ExitNodeAvailable || snap.ExitNodeActive {
		t.Fatalf("unexpected exit node status: %+v", snap)
	}
	if len(snap.DNSDomains) != 2 {
		t.Fatalf("unexpected DNS domains in snapshot: %+v", snap.DNSDomains)
	}

	// Sniffed/proxy domain targets resolve to overlay IP before dialing client.DialContext.
	var dialedDest string
	client.dialContextFn = func(_ context.Context, _ string, address string) (stdnet.Conn, error) {
		dialedDest = address
		return nil, stderrors.New("stop after capture")
	}
	link, _ := newPipeLink(t)
	_ = h.Process(newOutboundCtx(net.TCPDestination(net.DomainAddress("nas.netbird.selfhosted"), 443)), link, nil)
	if dialedDest != "100.77.0.10:443" {
		t.Fatalf("expected domain target to resolve to 100.77.0.10:443 before DialContext, got %q", dialedDest)
	}
}
