package conf_test

import (
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/netbird"
)

func TestNetBirdConfig(t *testing.T) {
	creator := func() Buildable {
		return new(NetBirdConfig)
	}

	portZero := int32(0)
	portCustom := int32(51820)
	lazyFalse := false

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"deviceName": "xray-node",
				"setupKey": "A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
				"managementUrl": "https://api.netbird.io",
				"configPath": "./nb-cfg.json",
				"statePath": "./nb-state.json",
				"mtu": 1400,
				"wireguardPort": 0,
				"disableClientRoutes": true,
				"disableIPv6": true,
				"blockLanAccess": true,
				"enableRosenpass": true,
				"rosenpassPermissive": true,
				"lazyConnection": false,
				"dnsLabels": ["corp", "internal"],
				"natExternalIPs": ["1.2.3.4/10.0.0.2"],
				"logLevel": "INFO"
			}`,
			Parser: loadJSON(creator),
			Output: &netbird.Config{
				DeviceName:          "xray-node",
				SetupKey:            "A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
				ManagementUrl:       "https://api.netbird.io",
				ConfigPath:          "./nb-cfg.json",
				StatePath:           "./nb-state.json",
				LogLevel:            "info",
				Mtu:                 1400,
				WireguardPort:       &portZero,
				DisableClientRoutes: true,
				DisableIpv6:         true,
				BlockInbound:        true,
				BlockLanAccess:      true,
				EnableRosenpass:     true,
				RosenpassPermissive: true,
				LazyConnection:      &lazyFalse,
				DnsLabels:           []string{"corp", "internal"},
				NatExternalIps:      []string{"1.2.3.4/10.0.0.2"},
				StartupTimeout:      30,
			},
		},
		{
			Input: `{
				"jwtToken": "jwt-secret",
				"blockInbound": false,
				"wireguardPort": 51820,
				"startupTimeout": 15
			}`,
			Parser: loadJSON(creator),
			Output: &netbird.Config{
				JwtToken:       "jwt-secret",
				WireguardPort:  &portCustom,
				BlockInbound:   false,
				StartupTimeout: 15,
			},
		},
		{
			Input: `{
				"privateKey": "priv-key",
				"preSharedKey": "psk"
			}`,
			Parser: loadJSON(creator),
			Output: &netbird.Config{
				PrivateKey:     "priv-key",
				PreSharedKey:   "psk",
				BlockInbound:   true,
				StartupTimeout: 30,
			},
		},
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &netbird.Config{
				BlockInbound:   true,
				StartupTimeout: 30,
			},
		},
	})

	invalidConfigs := []string{
		`{"setupKey": "a", "jwtToken": "b"}`,
		`{"setupKey": "a", "mtu": 500}`,
		`{"setupKey": "a", "mtu": 9000}`,
		`{"setupKey": "a", "wireguardPort": -1}`,
		`{"setupKey": "a", "wireguardPort": 70000}`,
		`{"setupKey": "a", "logLevel": "verbose"}`,
	}

	for _, raw := range invalidConfigs {
		if _, err := loadJSON(creator)(raw); err == nil {
			t.Errorf("expected error for invalid config %s, got nil", raw)
		}
	}
}
