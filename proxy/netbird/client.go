package netbird

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
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
	defaultStartupTimeout = 30 * time.Second
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
}

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
	client          netbirdClient
	startupTimeout  time.Duration
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	mu           sync.Mutex
	state        clientState
	startCancel  context.CancelFunc
	startDone    chan struct{}
	lastStartErr error
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

	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter
	if fh := session.FullHandlerFromContext(ctx); fh != nil {
		tag := fh.Tag()
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

	embedInitMu.Lock()
	client, err := embed.New(opts)
	embedInitMu.Unlock()
	if err != nil {
		return nil, errors.New("failed to create netbird client").Base(err)
	}

	startupTimeout := time.Duration(conf.StartupTimeout) * time.Second
	if startupTimeout <= 0 {
		startupTimeout = defaultStartupTimeout
	}

	return newHandler(p, client, startupTimeout, uplinkCounter, downlinkCounter, true), nil
}

func newHandler(p policy.Manager, client netbirdClient, startupTimeout time.Duration, uplinkCounter, downlinkCounter stats.Counter, autoStart bool) *Handler {
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
	if creds == 0 {
		return errors.New("one of setupKey, jwtToken, or privateKey must be provided")
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
	startCtx, cancel := context.WithTimeout(context.Background(), h.startupTimeout)
	done := make(chan struct{})
	h.startCancel = cancel
	h.startDone = done

	go func() {
		err := h.client.Start(startCtx)
		cancel()

		h.mu.Lock()
		if h.startDone == done {
			h.startCancel = nil
		}
		if h.state == stateClosed {
			h.mu.Unlock()
			if err == nil {
				stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
				_ = h.client.Stop(stopCtx)
				stopCancel()
			}
			close(done)
			return
		}

		if err == nil {
			h.state = stateStarted
			h.lastStartErr = nil
		} else {
			h.state = stateIdle
			h.lastStartErr = err
			errors.LogWarningInner(context.Background(), err, "netbird client start failed")
		}
		close(done)
		h.mu.Unlock()
	}()
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

	err := h.ensureStarted(dialCtx)
	if err != nil {
		if dialCancel != nil {
			dialCancel()
		}
		return err
	}

	var reader buf.Reader
	var writer buf.Writer

	switch ob.Target.Network {
	case net.Network_TCP:
		conn, err := h.client.DialContext(dialCtx, "tcp", ob.Target.NetAddr())
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
			pktConn, err := h.client.ListenUDP(":0")
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
			conn, err := h.client.DialContext(dialCtx, "udp", ob.Target.NetAddr())
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
	h.mu.Lock()
	if h.state == stateClosed {
		h.mu.Unlock()
		return nil
	}
	wasStarted := h.state == stateStarted
	cancel := h.startCancel
	done := h.startDone
	h.state = stateClosed
	h.startCancel = nil
	h.mu.Unlock()

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
	if wasStarted {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stopCancel()
		return h.client.Stop(stopCtx)
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
