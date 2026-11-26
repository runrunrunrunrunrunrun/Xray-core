package router_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/testing/mocks"
)

type stubNetBirdRouteMatcher struct {
	matchFn func(domain string, ips []net.IP, mode routing.NetBirdRouteMode) bool
}

func (s stubNetBirdRouteMatcher) MatchTarget(domain string, ips []net.IP, mode routing.NetBirdRouteMode) bool {
	return s.matchFn(domain, ips, mode)
}

func TestRouterNetBirdAttributeRules(t *testing.T) {
	const tag = "nb-router-attr-test"
	routing.RegisterNetBirdRouteMatcher(tag, stubNetBirdRouteMatcher{
		matchFn: func(domain string, ips []net.IP, mode routing.NetBirdRouteMode) bool {
			if mode == routing.NetBirdRouteModeExit {
				return false
			}
			if domain == "peer.netbird.selfhosted" {
				return true
			}
			for _, ip := range ips {
				if ip.String() == "100.64.0.9" || ip.String() == "10.200.0.5" {
					return true
				}
			}
			return false
		},
	})
	defer routing.UnregisterNetBirdRouteMatcher(tag)

	rawRouter := `{
		"domainStrategy": "IPIfNonMatch",
		"rules": [
			{
				"ruleTag": "app-netbird-routes",
				"inboundTag": ["tunIn"],
				"attrs": {"netbird": "routes", "netbirdTag": "` + tag + `"},
				"outboundTag": "` + tag + `"
			},
			{
				"ruleTag": "app-netbird-exit",
				"inboundTag": ["tunIn"],
				"attrs": {"netbird": "exit", "netbirdTag": "` + tag + `"},
				"outboundTag": "` + tag + `"
			}
		]
	}`

	var routerConf conf.RouterConfig
	if err := json.Unmarshal([]byte(rawRouter), &routerConf); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	pbConfig, err := routerConf.Build()
	if err != nil {
		t.Fatalf("RouterConfig.Build failed: %v", err)
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	// Expect Pass-2 DNS lookup for resolved-to-nb.example when Pass-1 didn't match.
	mockDNS.EXPECT().LookupIP("resolved-to-nb.example", gomock.Any()).Return(
		[]net.IP{net.ParseAddress("10.200.0.5").IP()}, uint32(60), nil,
	).Times(1)

	r := new(Router)
	common.Must(r.Init(context.TODO(), pbConfig, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	pick := func(dest net.Destination) (routing.Route, error) {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "tunIn"})
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
		return r.PickRoute(routing_session.AsRoutingContext(ctx))
	}

	// Pass-1 domain match.
	route, err := pick(net.TCPDestination(net.DomainAddress("peer.netbird.selfhosted"), 443))
	if err != nil || route.GetOutboundTag() != tag || route.GetRuleTag() != "app-netbird-routes" {
		t.Fatalf("unexpected Pass-1 domain route: %v, err=%v", route, err)
	}

	// Pass-1 IP match.
	route, err = pick(net.TCPDestination(net.ParseAddress("100.64.0.9"), 80))
	if err != nil || route.GetOutboundTag() != tag {
		t.Fatalf("unexpected Pass-1 IP route: %v, err=%v", route, err)
	}

	// Pass-2 IpIfNonMatch CIDR match after DNS resolution.
	route, err = pick(net.TCPDestination(net.DomainAddress("resolved-to-nb.example"), 80))
	if err != nil || route.GetOutboundTag() != tag || route.GetRuleTag() != "app-netbird-routes" {
		t.Fatalf("unexpected Pass-2 IP route: %v, err=%v", route, err)
	}
}
