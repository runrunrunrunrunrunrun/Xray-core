package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/netbird"
	"google.golang.org/protobuf/proto"
)

type NetBirdConfig struct {
	DeviceName          string   `json:"deviceName"`
	SetupKey            string   `json:"setupKey"`
	JWTToken            string   `json:"jwtToken"`
	PrivateKey          string   `json:"privateKey"`
	ManagementURL       string   `json:"managementUrl"`
	PreSharedKey        string   `json:"preSharedKey"`
	ConfigPath          string   `json:"configPath"`
	StatePath           string   `json:"statePath"`
	LogLevel            string   `json:"logLevel"`
	MTU                 uint32   `json:"mtu"`
	WireguardPort       *int32   `json:"wireguardPort"`
	DisableClientRoutes bool     `json:"disableClientRoutes"`
	DisableIPv6         bool     `json:"disableIPv6"`
	BlockInbound        *bool    `json:"blockInbound"`
	BlockLANAccess      bool     `json:"blockLanAccess"`
	EnableRosenpass     bool     `json:"enableRosenpass"`
	RosenpassPermissive bool     `json:"rosenpassPermissive"`
	LazyConnection      *bool    `json:"lazyConnection"`
	DNSLabels           []string `json:"dnsLabels"`
	NATExternalIPs      []string `json:"natExternalIPs"`
	StartupTimeout      uint32   `json:"startupTimeout"`
	EnableExitNode      bool     `json:"enableExitNode"`
}

func (c *NetBirdConfig) Build() (proto.Message, error) {
	creds := 0
	if c.SetupKey != "" {
		creds++
	}
	if c.JWTToken != "" {
		creds++
	}
	if c.PrivateKey != "" {
		creds++
	}
	if creds > 1 {
		return nil, errors.New("only one of setupKey, jwtToken, or privateKey can be specified")
	}

	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 8192) {
		return nil, errors.New("mtu must be between 576 and 8192")
	}

	if c.WireguardPort != nil && (*c.WireguardPort < 0 || *c.WireguardPort > 65535) {
		return nil, errors.New("wireguardPort must be between 0 and 65535")
	}

	logLevel := strings.ToLower(strings.TrimSpace(c.LogLevel))
	if logLevel != "" {
		switch logLevel {
		case "panic", "fatal", "error", "warn", "warning", "info", "debug", "trace":
		default:
			return nil, errors.New("invalid netbird logLevel: ", c.LogLevel)
		}
	}

	blockInbound := true
	if c.BlockInbound != nil {
		blockInbound = *c.BlockInbound
	}

	startupTimeout := c.StartupTimeout
	if startupTimeout == 0 {
		startupTimeout = 60
	}

	config := &netbird.Config{
		DeviceName:          c.DeviceName,
		SetupKey:            c.SetupKey,
		JwtToken:            c.JWTToken,
		PrivateKey:          c.PrivateKey,
		ManagementUrl:       c.ManagementURL,
		PreSharedKey:        c.PreSharedKey,
		ConfigPath:          c.ConfigPath,
		StatePath:           c.StatePath,
		LogLevel:            logLevel,
		Mtu:                 c.MTU,
		DisableClientRoutes: c.DisableClientRoutes,
		DisableIpv6:         c.DisableIPv6,
		BlockInbound:        blockInbound,
		BlockLanAccess:      c.BlockLANAccess,
		EnableRosenpass:     c.EnableRosenpass,
		RosenpassPermissive: c.RosenpassPermissive,
		DnsLabels:           c.DNSLabels,
		NatExternalIps:      c.NATExternalIPs,
		StartupTimeout:      startupTimeout,
		EnableExitNode:      c.EnableExitNode,
	}

	if c.WireguardPort != nil {
		port := *c.WireguardPort
		config.WireguardPort = &port
	}
	if c.LazyConnection != nil {
		lazy := *c.LazyConnection
		config.LazyConnection = &lazy
	}

	return config, nil
}
