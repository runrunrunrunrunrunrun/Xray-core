package netbird

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	defaultStartupTimeout = 60 * time.Second
	shutdownTimeout       = 5 * time.Second
)

// embedInitMu serializes embed.New calls because NetBird's embed package
// mutates process-wide environment variables and global logrus settings.
var embedInitMu sync.Mutex

type netbirdClient interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenUDP(address string) (net.PacketConn, error)
	StatusSnapshot() (*StatusDetail, error)
	RoutingTable() (embed.RoutingTable, error)
	MatchDNSDomain(domain string) bool
	LookupIP(ctx context.Context, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error)
}

type (
	clientFactoryFn func(opts embed.Options) (netbirdClient, error)
	oauthLoginFn    func(ctx context.Context, managementURL, existingPrivateKey string) (string, error)
)

type clientState uint8

const (
	stateIdle clientState = iota
	stateStarting
	stateStarted
	stateClosed
)

// Handler implements proxy.Outbound for the NetBird embedded userspace client.
type Handler struct {
	policyManager   policy.Manager
	startupTimeout  time.Duration
	oauthTimeout    time.Duration
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
	registryKey     string

	oauthMode       bool
	outboundIface   string
	ifaceAcquired   bool
	baseOpts        embed.Options
	managementURL   string
	configPath      string
	instanceStarted <-chan struct{}
	newClientFn     clientFactoryFn
	oauthLoginFn    oauthLoginFn

	mu                 sync.Mutex
	client             netbirdClient
	state              clientState
	enableExitNode     bool
	routeSnap          atomic.Pointer[routeSnapshot]
	routeRefreshCancel context.CancelFunc
	extraPrefixesMu    sync.Mutex
	extraPrefixes      []netip.Prefix
	startCancel        context.CancelFunc
	startDone          chan struct{}
	lastStartErr       error
}

func defaultNewClient(opts embed.Options) (netbirdClient, error) {
	embedInitMu.Lock()
	defer embedInitMu.Unlock()
	c, err := embed.New(opts)
	if err != nil {
		return nil, err
	}
	return embedClientAdapter{Client: c}, nil
}

// NewClient creates a new NetBird outbound handler and begins connecting in the background.
func NewClient(ctx context.Context, conf *Config) (*Handler, error) {
	if conf == nil {
		return nil, errors.New("netbird config is nil")
	}
	if err := validateConfig(conf); err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	var tag string
	var outboundIface string
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter
	if ss, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok && ss != nil && ss.SocketSettings != nil {
		outboundIface = strings.TrimSpace(ss.SocketSettings.Interface)
	}
	if fh := session.FullHandlerFromContext(ctx); fh != nil {
		tag = fh.Tag()
		if len(tag) > 0 && p.ForSystem().Stats.OutboundUplink {
			statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
			if c, _ := statsManager.GetOrRegisterCounter("outbound>>>" + tag + ">>>traffic>>>uplink"); c != nil {
				uplinkCounter = c
			}
		}
		if len(tag) > 0 && p.ForSystem().Stats.OutboundDownlink {
			statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
			if c, _ := statsManager.GetOrRegisterCounter("outbound>>>" + tag + ">>>traffic>>>downlink"); c != nil {
				downlinkCounter = c
			}
		}
	}

	logLevel := conf.LogLevel
	if logLevel == "" {
		logLevel = "warn"
	}

	opts := embed.Options{
		DeviceName:          conf.DeviceName,
		SetupKey:            conf.SetupKey,
		JWTToken:            conf.JwtToken,
		PrivateKey:          conf.PrivateKey,
		ManagementURL:       conf.ManagementUrl,
		PreSharedKey:        conf.PreSharedKey,
		LogOutput:           newXrayLogWriter(),
		LogLevel:            logLevel,
		NoUserspace:         false,
		ConfigPath:          conf.ConfigPath,
		StatePath:           conf.StatePath,
		DisableClientRoutes: conf.DisableClientRoutes,
		EnableExitNode:      conf.EnableExitNode,
		DisableIPv6:         conf.DisableIpv6,
		BlockInbound:        conf.BlockInbound,
		BlockLANAccess:      conf.BlockLanAccess,
		EnableRosenpass:     conf.EnableRosenpass,
		RosenpassPermissive: conf.RosenpassPermissive,
		DNSLabels:           conf.DnsLabels,
		NATExternalIPs:      conf.NatExternalIps,
	}
	if conf.LazyConnection != nil {
		lazy := *conf.LazyConnection
		opts.LazyConnectionEnabled = &lazy
	}
	if conf.WireguardPort != nil {
		port := int(*conf.WireguardPort)
		opts.WireguardPort = &port
	}
	if conf.Mtu != 0 {
		mtu := uint16(conf.Mtu)
		opts.MTU = &mtu
	}

	startupTimeout := time.Duration(conf.StartupTimeout) * time.Second
	if startupTimeout <= 0 {
		startupTimeout = defaultStartupTimeout
	}

	oauthMode := conf.SetupKey == "" && conf.JwtToken == "" && conf.PrivateKey == ""
	h := &Handler{
		policyManager:   p,
		startupTimeout:  startupTimeout,
		oauthTimeout:    defaultOAuthTimeout,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
		oauthMode:       oauthMode,
		outboundIface:   outboundIface,
		baseOpts:        opts,
		managementURL:   conf.ManagementUrl,
		configPath:      conf.ConfigPath,
		instanceStarted: v.Started(),
		newClientFn:     defaultNewClient,
		oauthLoginFn:    obtainOAuthToken,
		state:           stateIdle,
		enableExitNode:  conf.EnableExitNode,
	}
	h.seedDefaultOverlay()
	h.registerHandler(tag)
	return h, nil
}

// Start implements common.Runnable and begins background NetBird startup.
func (h *Handler) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state == stateIdle {
		h.acquireOutboundInterfaceLocked()
		h.triggerStartLocked()
	}
	return nil
}

func (h *Handler) acquireOutboundInterfaceLocked() {
	if h.outboundIface != "" && !h.ifaceAcquired {
		acquireHandlerOutboundInterface(h.outboundIface)
		h.ifaceAcquired = true
	}
}

func newHandler(p policy.Manager, client netbirdClient, startupTimeout time.Duration, uplinkCounter, downlinkCounter stats.Counter, autoStart bool) *Handler {
	return newHandlerWithTag("", p, client, startupTimeout, uplinkCounter, downlinkCounter, autoStart)
}

func newHandlerWithTag(tag string, p policy.Manager, client netbirdClient, startupTimeout time.Duration, uplinkCounter, downlinkCounter stats.Counter, autoStart bool) *Handler {
	if startupTimeout <= 0 {
		startupTimeout = defaultStartupTimeout
	}
	h := &Handler{
		policyManager:   p,
		client:          client,
		startupTimeout:  startupTimeout,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
		state:           stateIdle,
	}
	h.seedDefaultOverlay()
	h.registerHandler(tag)
	if autoStart {
		h.mu.Lock()
		h.triggerStartLocked()
		h.mu.Unlock()
	}
	return h
}

func newOAuthHandler(
	p policy.Manager,
	baseOpts embed.Options,
	managementURL string,
	configPath string,
	startupTimeout time.Duration,
	oauthTimeout time.Duration,
	uplinkCounter stats.Counter,
	downlinkCounter stats.Counter,
	newClientFn clientFactoryFn,
	oauthLoginFn oauthLoginFn,
	autoStart bool,
) *Handler {
	return newOAuthHandlerWithTag("", p, baseOpts, managementURL, configPath, startupTimeout, oauthTimeout, uplinkCounter, downlinkCounter, newClientFn, oauthLoginFn, autoStart)
}

func newOAuthHandlerWithTag(
	tag string,
	p policy.Manager,
	baseOpts embed.Options,
	managementURL string,
	configPath string,
	startupTimeout time.Duration,
	oauthTimeout time.Duration,
	uplinkCounter stats.Counter,
	downlinkCounter stats.Counter,
	newClientFn clientFactoryFn,
	oauthLoginFn oauthLoginFn,
	autoStart bool,
) *Handler {
	if startupTimeout <= 0 {
		startupTimeout = defaultStartupTimeout
	}
	if oauthTimeout <= 0 {
		oauthTimeout = defaultOAuthTimeout
	}
	h := &Handler{
		policyManager:   p,
		startupTimeout:  startupTimeout,
		oauthTimeout:    oauthTimeout,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
		oauthMode:       true,
		baseOpts:        baseOpts,
		managementURL:   managementURL,
		configPath:      configPath,
		newClientFn:     newClientFn,
		oauthLoginFn:    oauthLoginFn,
		state:           stateIdle,
	}
	h.seedDefaultOverlay()
	h.registerHandler(tag)
	if autoStart {
		h.mu.Lock()
		h.triggerStartLocked()
		h.mu.Unlock()
	}
	return h
}

func validateConfig(conf *Config) error {
	creds := 0
	if conf.SetupKey != "" {
		creds++
	}
	if conf.JwtToken != "" {
		creds++
	}
	if conf.PrivateKey != "" {
		creds++
	}
	if creds > 1 {
		return errors.New("only one of setupKey, jwtToken, or privateKey can be specified")
	}
	if conf.Mtu != 0 && (conf.Mtu < 576 || conf.Mtu > 8192) {
		return errors.New("mtu must be between 576 and 8192")
	}
	if conf.WireguardPort != nil && (*conf.WireguardPort < 0 || *conf.WireguardPort > 65535) {
		return errors.New("wireguardPort must be between 0 and 65535")
	}
	return nil
}

func (h *Handler) triggerStartLocked() {
	h.state = stateStarting
	h.registerRoutingHooks()
	totalTimeout := h.startupTimeout
	if h.oauthMode {
		totalTimeout = h.oauthTimeout + h.startupTimeout
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	startedCh := h.instanceStarted
	h.startCancel = cancel
	h.startDone = done

	go func() {
		var client netbirdClient
		var err error
		if startedCh != nil {
			select {
			case <-startedCh:
			case <-baseCtx.Done():
				err = baseCtx.Err()
			}
		}
		if err == nil {
			startCtx, timeoutCancel := context.WithTimeout(baseCtx, totalTimeout)
			client, err = h.startClient(startCtx)
			timeoutCancel()
		}
		cancel()

		if err == nil && client != nil {
			h.refreshRouteSnapshotFromClient(client)
		}

		h.mu.Lock()
		if h.startDone == done {
			h.startCancel = nil
		}
		if h.state == stateClosed {
			h.mu.Unlock()
			if err == nil && client != nil {
				stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
				_ = client.Stop(stopCtx)
				stopCancel()
			}
			close(done)
			return
		}

		if err == nil {
			h.client = client
			h.state = stateStarted
			h.lastStartErr = nil
			h.startRouteRefreshLocked()
		} else {
			h.state = stateIdle
			h.lastStartErr = err
			errors.LogWarningInner(context.Background(), err, "netbird client start failed")
		}
		close(done)
		h.mu.Unlock()
	}()
}

func (h *Handler) setClient(c netbirdClient) {
	h.mu.Lock()
	if h.state != stateClosed {
		h.client = c
	}
	h.mu.Unlock()
}

func (h *Handler) startClient(startCtx context.Context) (netbirdClient, error) {
	if !h.oauthMode {
		h.mu.Lock()
		client := h.client
		factory := h.newClientFn
		if factory == nil {
			factory = defaultNewClient
		}
		opts := h.baseOpts
		h.mu.Unlock()

		if client == nil {
			var err error
			client, err = factory(opts)
			if err != nil {
				return nil, errors.New("failed to create netbird client").Base(err)
			}
			h.setClient(client)
		}
		if err := client.Start(startCtx); err != nil {
			return nil, err
		}
		return client, nil
	}

	existingKey := readPrivateKeyFromConfig(h.configPath)
	if existingKey != "" {
		opts := h.baseOpts
		opts.PrivateKey = existingKey
		opts.JWTToken = ""
		opts.SetupKey = ""

		if c, err := h.newClientFn(opts); err == nil {
			h.setClient(c)
			connectCtx, connectCancel := context.WithTimeout(startCtx, h.startupTimeout)
			startErr := c.Start(connectCtx)
			connectCancel()
			if startErr == nil {
				return c, nil
			}
			if startCtx.Err() != nil {
				return nil, startCtx.Err()
			}
			errors.LogWarningInner(context.Background(), startErr, "netbird saved peer login failed, starting interactive OAuth")
		} else {
			errors.LogWarningInner(context.Background(), err, "netbird saved peer init failed, starting interactive OAuth")
		}
	}

	oauthCtx, oauthCancel := context.WithTimeout(startCtx, h.oauthTimeout)
	jwtToken, err := h.oauthLoginFn(oauthCtx, h.managementURL, existingKey)
	oauthCancel()
	if err != nil {
		return nil, err
	}

	opts := h.baseOpts
	opts.JWTToken = jwtToken
	opts.PrivateKey = ""
	opts.SetupKey = ""

	c, err := h.newClientFn(opts)
	if err != nil {
		return nil, errors.New("failed to create netbird client after OAuth").Base(err)
	}
	h.setClient(c)

	connectCtx, connectCancel := context.WithTimeout(startCtx, h.startupTimeout)
	defer connectCancel()
	if err := c.Start(connectCtx); err != nil {
		return nil, err
	}
	return c, nil
}

func (h *Handler) ensureStarted(ctx context.Context) error {
	h.mu.Lock()
	switch h.state {
	case stateStarted:
		h.mu.Unlock()
		return nil
	case stateClosed:
		h.mu.Unlock()
		return errors.New("netbird client closed")
	case stateIdle:
		h.acquireOutboundInterfaceLocked()
		h.triggerStartLocked()
	}
	done := h.startDone
	h.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	switch h.state {
	case stateStarted:
		return nil
	case stateClosed:
		return errors.New("netbird client closed")
	default:
		return errors.New("failed to start netbird client").Base(h.lastStartErr)
	}
}

func (h *Handler) getClient() netbirdClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.client
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "netbird"
	ob.CanSpliceCopy = 3
	if dialer != nil {
		dialer.SetOutboundGateway(ctx, ob)
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	if newCtx != nil {
		ctx = newCtx
	}

	dialCtx := ctx
	var dialCancel context.CancelFunc
	if sessionPolicy.Timeouts.Handshake != 0 {
		dialCtx, dialCancel = context.WithTimeout(ctx, sessionPolicy.Timeouts.Handshake)
	}

	if err := h.ensureStarted(dialCtx); err != nil {
		if dialCancel != nil {
			dialCancel()
		}
		return err
	}

	client := h.getClient()
	if client == nil {
		if dialCancel != nil {
			dialCancel()
		}
		return errors.New("netbird client not initialized")
	}

	var reader buf.Reader
	var writer buf.Writer

	switch ob.Target.Network {
	case net.Network_TCP:
		conn, err := client.DialContext(dialCtx, "tcp", ob.Target.NetAddr())
		if dialCancel != nil {
			dialCancel()
		}
		if err != nil {
			return errors.New("failed to create TCP connection").Base(err)
		}
		defer conn.Close()
		if h.uplinkCounter != nil || h.downlinkCounter != nil {
			conn = &stat.CounterConnection{
				Connection:   conn,
				ReadCounter:  h.downlinkCounter,
				WriteCounter: h.uplinkCounter,
			}
		}
		reader = buf.NewReader(conn)
		writer = buf.NewWriter(conn)

	case net.Network_UDP:
		if ob.Target.Address.Family().IsIPv4() {
			if dialCancel != nil {
				dialCancel()
			}
			// ListenUDP(":0") binds NetBird's primary IPv4 tunnel address and supports
			// Full-Cone multi-destination UDP just like Xray's wireguard outbound.
			pktConn, err := client.ListenUDP(":0")
			if err != nil {
				return errors.New("failed to create UDP listener").Base(err)
			}
			defer pktConn.Close()
			if h.uplinkCounter != nil || h.downlinkCounter != nil {
				pktConn = &packetCounterConn{
					PacketConn:   pktConn,
					ReadCounter:  h.downlinkCounter,
					WriteCounter: h.uplinkCounter,
				}
			}
			c := &udpConnClient{
				PacketConn: pktConn,
				Dest: &net.UDPAddr{
					IP:   ob.Target.Address.IP(),
					Port: int(ob.Target.Port),
				},
			}
			reader = c
			writer = c
		} else {
			// Domain and IPv6 UDP targets use DialContext so NetBird's netstack DNS
			// resolves domain names and gVisor selects the matching IP protocol stack.
			conn, err := client.DialContext(dialCtx, "udp", ob.Target.NetAddr())
			if dialCancel != nil {
				dialCancel()
			}
			if err != nil {
				return errors.New("failed to create UDP connection").Base(err)
			}
			defer conn.Close()
			remoteDest := ob.Target
			if udpAddr, ok := conn.RemoteAddr().(*net.UDPAddr); ok && udpAddr != nil {
				remoteDest = net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port))
			}
			if h.uplinkCounter != nil || h.downlinkCounter != nil {
				conn = &stat.CounterConnection{
					Connection:   conn,
					ReadCounter:  h.downlinkCounter,
					WriteCounter: h.uplinkCounter,
				}
			}
			c := &connectedUDPClient{
				conn:       conn,
				remoteDest: remoteDest,
			}
			reader = c
			writer = c
		}

	default:
		if dialCancel != nil {
			dialCancel()
		}
		return errors.New("unsupported network: ", ob.Target.Network)
	}

	requestFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}

	responseFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err)
	}

	return nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	h.unregisterRoutingHooks()
	h.unregisterHandler()

	h.mu.Lock()
	if h.state == stateClosed {
		h.mu.Unlock()
		return nil
	}
	wasStarted := h.state == stateStarted
	client := h.client
	cancel := h.startCancel
	routeCancel := h.routeRefreshCancel
	done := h.startDone
	outboundIface := ""
	if h.ifaceAcquired {
		outboundIface = h.outboundIface
		h.ifaceAcquired = false
	}
	h.state = stateClosed
	h.startCancel = nil
	h.routeRefreshCancel = nil
	h.mu.Unlock()
	defer releaseHandlerOutboundInterface(outboundIface)

	if routeCancel != nil {
		routeCancel()
	}
	if cancel != nil {
		cancel()
	}
	if done != nil {
		timer := time.NewTimer(shutdownTimeout)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
		}
	}
	if wasStarted && client != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stopCancel()
		return client.Stop(stopCtx)
	}
	return nil
}

type udpConnClient struct {
	net.PacketConn
	Dest *net.UDPAddr
}

func (c *udpConnClient) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := c.PacketConn.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))

	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr != nil {
		b.UDP = &net.Destination{
			Address: net.IPAddress(udpAddr.IP),
			Port:    net.Port(udpAddr.Port),
			Network: net.Network_UDP,
		}
	} else if addr != nil {
		dest := net.DestinationFromAddr(addr)
		b.UDP = &dest
	}

	return buf.MultiBuffer{b}, nil
}

func (c *udpConnClient) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.Dest
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				if b.UDP.Port != net.Port(dst.Port) {
					dst = &net.UDPAddr{IP: dst.IP, Port: int(b.UDP.Port)}
				}
			} else if b.UDP.Address.Family().IsIPv4() {
				dst = b.UDP.RawNetAddr().(*net.UDPAddr)
			}
		}
		if _, err := c.PacketConn.WriteTo(b.Bytes(), dst); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

type connectedUDPClient struct {
	conn       net.Conn
	remoteDest net.Destination
}

func (c *connectedUDPClient) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, err := c.conn.Read(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	dest := c.remoteDest
	b.UDP = &dest
	return buf.MultiBuffer{b}, nil
}

func (c *connectedUDPClient) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		if _, err := c.conn.Write(b.Bytes()); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

type packetCounterConn struct {
	net.PacketConn
	ReadCounter  stats.Counter
	WriteCounter stats.Counter
}

func (c *packetCounterConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err == nil && c.ReadCounter != nil {
		c.ReadCounter.Add(int64(n))
	}
	return
}

func (c *packetCounterConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	if err == nil && c.WriteCounter != nil {
		c.WriteCounter.Add(int64(n))
	}
	return
}

type xrayLogWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newXrayLogWriter() io.Writer {
	return &xrayLogWriter{}
}

func (w *xrayLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, _ = w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			if len(line) > 0 {
				w.buf.WriteString(line)
			}
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		log.Record(&log.GeneralMessage{
			Severity: parseLogSeverity(trimmed),
			Content:  "netbird: " + trimmed,
		})
	}
	return len(p), nil
}

func parseLogSeverity(line string) log.Severity {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "level=error"), strings.Contains(lower, "level=fatal"), strings.Contains(lower, "level=panic"), strings.Contains(lower, " error "):
		return log.Severity_Error
	case strings.Contains(lower, "level=warn"), strings.Contains(lower, "level=warning"), strings.Contains(lower, " warn "):
		return log.Severity_Warning
	case strings.Contains(lower, "level=info"), strings.Contains(lower, " info "):
		return log.Severity_Info
	default:
		return log.Severity_Debug
	}
}
