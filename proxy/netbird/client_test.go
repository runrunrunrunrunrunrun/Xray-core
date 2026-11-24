package netbird

import (
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featurepolicy "github.com/xtls/xray-core/features/policy"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type fakeNetbirdClient struct {
	startFn       func(ctx context.Context) error
	stopFn        func(ctx context.Context) error
	dialContextFn func(ctx context.Context, network, address string) (net.Conn, error)
	listenUDPFn   func(address string) (net.PacketConn, error)

	startCalls atomic.Int32
	stopCalls  atomic.Int32
}

func (f *fakeNetbirdClient) Start(ctx context.Context) error {
	f.startCalls.Add(1)
	if f.startFn != nil {
		return f.startFn(ctx)
	}
	return nil
}

func (f *fakeNetbirdClient) Stop(ctx context.Context) error {
	f.stopCalls.Add(1)
	if f.stopFn != nil {
		return f.stopFn(ctx)
	}
	return nil
}

func (f *fakeNetbirdClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if f.dialContextFn != nil {
		return f.dialContextFn(ctx, network, address)
	}
	return nil, stderrors.New("dialContextFn not configured")
}

func (f *fakeNetbirdClient) ListenUDP(address string) (net.PacketConn, error) {
	if f.listenUDPFn != nil {
		return f.listenUDPFn(address)
	}
	return nil, stderrors.New("listenUDPFn not configured")
}

func newTestPolicyManager(t *testing.T) featurepolicy.Manager {
	t.Helper()
	pm, err := policy.New(context.Background(), &policy.Config{})
	if err != nil {
		t.Fatalf("failed to create policy manager: %v", err)
	}
	return pm
}

func newTestStatsCounters(t *testing.T) (featurestats.Counter, featurestats.Counter) {
	t.Helper()
	sm, err := stats.NewManager(context.Background(), &stats.Config{})
	if err != nil {
		t.Fatalf("failed to create stats manager: %v", err)
	}
	up, err := sm.RegisterCounter("outbound>>>netbird-test>>>traffic>>>uplink")
	if err != nil {
		t.Fatalf("failed to register uplink counter: %v", err)
	}
	down, err := sm.RegisterCounter("outbound>>>netbird-test>>>traffic>>>downlink")
	if err != nil {
		t.Fatalf("failed to register downlink counter: %v", err)
	}
	return up, down
}

func newOutboundCtx(dest net.Destination) context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: dest},
	})
}

func newPipeLink(t *testing.T) (clientLink *transport.Link, serverLink *transport.Link) {
	t.Helper()
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
	return &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}
}

type fakePacketConn struct {
	mu      sync.Mutex
	inCh    chan packetMsg
	outList []packetMsg
	closed  atomic.Bool
}

type packetMsg struct {
	data []byte
	addr net.Addr
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		inCh: make(chan packetMsg, 8),
	}
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	msg, ok := <-c.inCh
	if !ok {
		return 0, nil, io.EOF
	}
	n := copy(p, msg.data)
	return n, msg.addr, nil
}

func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	cp := append([]byte(nil), p...)
	c.mu.Lock()
	c.outList = append(c.outList, packetMsg{data: cp, addr: addr})
	c.mu.Unlock()
	return len(p), nil
}

func (c *fakePacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.inCh)
	}
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: stdnet.IPv4(100, 64, 0, 1), Port: 40000}
}

func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type fakeDatagramConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *fakeDatagramConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func TestValidateConfig(t *testing.T) {
	validPort := int32(51820)
	invalidPort := int32(70000)

	tests := []struct {
		name    string
		conf    *Config
		wantErr bool
	}{
		{
			name:    "valid setup key",
			conf:    &Config{SetupKey: "key", Mtu: 1280, WireguardPort: &validPort},
			wantErr: false,
		},
		{
			name:    "missing credentials",
			conf:    &Config{},
			wantErr: true,
		},
		{
			name:    "multiple credentials",
			conf:    &Config{SetupKey: "a", PrivateKey: "b"},
			wantErr: true,
		},
		{
			name:    "mtu too small",
			conf:    &Config{SetupKey: "key", Mtu: 500},
			wantErr: true,
		},
		{
			name:    "mtu too large",
			conf:    &Config{SetupKey: "key", Mtu: 9000},
			wantErr: true,
		},
		{
			name:    "invalid port",
			conf:    &Config{SetupKey: "key", WireguardPort: &invalidPort},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(tc.conf)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestHandlerTCPProcessAndStats(t *testing.T) {
	up, down := newTestStatsCounters(t)
	pm := newTestPolicyManager(t)

	var dialedNetwork, dialedAddr string
	client := &fakeNetbirdClient{
		dialContextFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedNetwork = network
			dialedAddr = address
			c1, c2 := stdnet.Pipe()
			go func() {
				defer c2.Close()
				buf := make([]byte, 64)
				n, err := c2.Read(buf)
				if err != nil {
					return
				}
				_, _ = c2.Write(buf[:n])
			}()
			return c1, nil
		},
	}

	h := newHandler(pm, client, time.Second, up, down, true)
	defer h.Close()

	callerLink, outboundLink := newPipeLink(t)
	dest := net.TCPDestination(net.DomainAddress("peer.netbird.cloud"), 8080)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Process(newOutboundCtx(dest), outboundLink, nil)
	}()

	payload := []byte("hello netbird")
	b := buf.New()
	b.Write(payload)
	if err := callerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("WriteMultiBuffer failed: %v", err)
	}
	common.Close(callerLink.Writer)

	mb, err := callerLink.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer failed: %v", err)
	}
	gotBuf := make([]byte, 64)
	n := mb.Copy(gotBuf)
	buf.ReleaseMulti(mb)

	if string(gotBuf[:n]) != string(payload) {
		t.Fatalf("got %q, want %q", string(gotBuf[:n]), string(payload))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if dialedNetwork != "tcp" || dialedAddr != "peer.netbird.cloud:8080" {
		t.Fatalf("unexpected dial args: %s %s", dialedNetwork, dialedAddr)
	}
	if up.Value() != int64(len(payload)) || down.Value() != int64(len(payload)) {
		t.Fatalf("unexpected counters: up=%d down=%d", up.Value(), down.Value())
	}
}

func TestHandlerIPv4FullConeUDP(t *testing.T) {
	up, down := newTestStatsCounters(t)
	pm := newTestPolicyManager(t)

	pktConn := newFakePacketConn()
	client := &fakeNetbirdClient{
		listenUDPFn: func(address string) (net.PacketConn, error) {
			if address != ":0" {
				t.Fatalf("unexpected ListenUDP address: %s", address)
			}
			return pktConn, nil
		},
	}

	h := newHandler(pm, client, time.Second, up, down, true)
	defer h.Close()

	callerLink, outboundLink := newPipeLink(t)
	dest := net.UDPDestination(net.IPAddress([]byte{100, 64, 0, 2}), 5353)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Process(newOutboundCtx(dest), outboundLink, nil)
	}()

	altDest := net.UDPDestination(net.IPAddress([]byte{100, 64, 0, 9}), 9999)
	b := buf.New()
	b.Write([]byte("ping-v4"))
	b.UDP = &altDest
	if err := callerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("WriteMultiBuffer failed: %v", err)
	}

	replyFrom := &net.UDPAddr{IP: stdnet.IPv4(100, 64, 0, 9), Port: 9999}
	pktConn.inCh <- packetMsg{data: []byte("pong-v4"), addr: replyFrom}

	mb, err := callerLink.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer failed: %v", err)
	}
	if len(mb) != 1 || mb[0].UDP == nil || mb[0].UDP.NetAddr() != "100.64.0.9:9999" {
		t.Fatalf("unexpected response b.UDP: %+v", mb)
	}
	buf.ReleaseMulti(mb)

	common.Close(callerLink.Writer)
	common.Interrupt(callerLink.Reader)
	<-errCh

	pktConn.mu.Lock()
	defer pktConn.mu.Unlock()
	if len(pktConn.outList) != 1 {
		t.Fatalf("expected 1 outbound packet, got %d", len(pktConn.outList))
	}
	if pktConn.outList[0].addr.String() != "100.64.0.9:9999" {
		t.Fatalf("unexpected outbound packet addr: %s", pktConn.outList[0].addr.String())
	}
	if up.Value() != 7 || down.Value() != 7 {
		t.Fatalf("unexpected counters: up=%d down=%d", up.Value(), down.Value())
	}
}

func TestHandlerDomainAndIPv6UDP(t *testing.T) {
	tests := []struct {
		name       string
		dest       net.Destination
		remoteAddr *net.UDPAddr
		wantUDP    string
	}{
		{
			name:       "domain UDP",
			dest:       net.UDPDestination(net.DomainAddress("dns.netbird.cloud"), 53),
			remoteAddr: &net.UDPAddr{IP: stdnet.IPv4(100, 64, 0, 10), Port: 53},
			wantUDP:    "100.64.0.10:53",
		},
		{
			name:       "IPv6 UDP",
			dest:       net.UDPDestination(net.ParseAddress("fd00::1"), 5353),
			remoteAddr: &net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: 5353},
			wantUDP:    "[fd00::1]:5353",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := newTestPolicyManager(t)
			client := &fakeNetbirdClient{
				dialContextFn: func(ctx context.Context, network, address string) (net.Conn, error) {
					if network != "udp" {
						t.Fatalf("expected udp network, got %s", network)
					}
					c1, c2 := stdnet.Pipe()
					go func() {
						defer c2.Close()
						buf := make([]byte, 64)
						n, err := c2.Read(buf)
						if err != nil {
							return
						}
						_, _ = c2.Write(buf[:n])
					}()
					return &fakeDatagramConn{Conn: c1, remoteAddr: tc.remoteAddr}, nil
				},
			}

			h := newHandler(pm, client, time.Second, nil, nil, true)
			defer h.Close()

			callerLink, outboundLink := newPipeLink(t)
			errCh := make(chan error, 1)
			go func() {
				errCh <- h.Process(newOutboundCtx(tc.dest), outboundLink, nil)
			}()

			b := buf.New()
			b.Write([]byte("dns-query"))
			if err := callerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				t.Fatalf("WriteMultiBuffer failed: %v", err)
			}
			common.Close(callerLink.Writer)

			mb, err := callerLink.Reader.ReadMultiBuffer()
			if err != nil {
				t.Fatalf("ReadMultiBuffer failed: %v", err)
			}
			if len(mb) != 1 || mb[0].UDP == nil || mb[0].UDP.NetAddr() != tc.wantUDP {
				t.Fatalf("got UDP addr %v, want %s", mb[0].UDP, tc.wantUDP)
			}
			buf.ReleaseMulti(mb)

			if err := <-errCh; err != nil {
				t.Fatalf("Process returned error: %v", err)
			}
		})
	}
}

func TestHandlerConcurrentEnsureStartedAndRetry(t *testing.T) {
	pm := newTestPolicyManager(t)
	var attempt atomic.Int32
	gate := make(chan struct{})

	client := &fakeNetbirdClient{
		startFn: func(ctx context.Context) error {
			if attempt.Add(1) == 1 {
				<-gate
				return stderrors.New("transient failure")
			}
			return nil
		},
	}

	h := newHandler(pm, client, 2*time.Second, nil, nil, true)
	defer h.Close()

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = h.ensureStarted(context.Background())
		}(i)
	}

	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := client.startCalls.Load(); got != 1 {
		t.Fatalf("expected 1 coalesced Start call, got %d", got)
	}
	for i, err := range errs {
		if err == nil {
			t.Fatalf("expected initial failure for waiter %d", i)
		}
	}

	// Next ensureStarted should retry and succeed.
	if err := h.ensureStarted(context.Background()); err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if got := client.startCalls.Load(); got != 2 {
		t.Fatalf("expected 2 total Start calls after retry, got %d", got)
	}
}

func TestHandlerCloseCancelsInFlightStartAndStopsStarted(t *testing.T) {
	pm := newTestPolicyManager(t)

	// Case 1: Close cancels in-flight Start.
	started := make(chan struct{})
	client1 := &fakeNetbirdClient{
		startFn: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	h1 := newHandler(pm, client1, 5*time.Second, nil, nil, true)
	<-started
	if err := h1.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if got := client1.stopCalls.Load(); got != 0 {
		t.Fatalf("expected 0 Stop calls when Start was cancelled, got %d", got)
	}

	// Case 2: Close races right as Start succeeds -> must still call Stop.
	allowFinish := make(chan struct{})
	inStart := make(chan struct{})
	client2 := &fakeNetbirdClient{
		startFn: func(ctx context.Context) error {
			close(inStart)
			<-allowFinish
			return nil
		},
	}
	h2 := newHandler(pm, client2, 5*time.Second, nil, nil, true)
	<-inStart
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- h2.Close()
	}()
	time.Sleep(20 * time.Millisecond)
	close(allowFinish)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if got := client2.stopCalls.Load(); got != 1 {
		t.Fatalf("expected 1 Stop call when Start succeeded during Close, got %d", got)
	}
}

var _ = core.Instance{}
