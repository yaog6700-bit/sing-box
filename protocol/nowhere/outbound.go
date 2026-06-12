//go:build with_quic

package nowhere

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	nowhereTransport "github.com/sagernet/sing-box/transport/nowhere"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NowhereOutboundOptions](registry, C.TypeNowhere, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *nowhereClient
}

type nowhereClient struct {
	mu      context.Context
	session *nowhereTransport.Session
	cfg     *nowhereTransport.Config
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereOutboundOptions) (adapter.Outbound, error) {
	tlsInsecure := false
	tlsServerName := options.Server
	if options.TLS != nil {
		tlsInsecure = options.TLS.Insecure
		if options.TLS.ServerName != "" {
			tlsServerName = options.TLS.ServerName
		}
	}

	cfg := &nowhereTransport.Config{
		Host:          options.Server,
		Port:          options.ServerPort,
		Key:           options.Key,
		Spec:          options.Spec,
		ALPN:          options.ALPN,
		TLSInsecure:   tlsInsecure,
		TLSServerName: tlsServerName,
	}

	// Validate config early (checks key/spec/alpn lengths, derives spec)
	if _, err := nowhereTransport.BuildEffectiveSpec(cfg.Key, cfg.Spec, cfg.ALPN); err != nil {
		return nil, err
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeNowhere, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:  logger,
		client: &nowhereClient{
			cfg: cfg,
		},
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		session, err := o.client.getSession()
		if err != nil {
			return nil, err
		}
		var conn net.Conn
		var dialErr error
		done := make(chan struct{})
		session.EnsureReady(func(e error) {
			defer close(done)
			if e != nil {
				dialErr = e
				return
			}
			conn, dialErr = nowhereTransport.NewConn(session, destination.String())
		})
		<-done
		return conn, dialErr
	default:
		return nil, N.ErrNoRoute
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	session, err := o.client.getSession()
	if err != nil {
		return nil, err
	}
	var udpConn *nowhereTransport.UDPConn
	var dialErr error
	done := make(chan struct{})
	session.EnsureReady(func(e error) {
		defer close(done)
		if e != nil {
			dialErr = e
			return
		}
		udpConn, dialErr = nowhereTransport.NewUDPConn(session, destination.String())
	})
	<-done
	if dialErr != nil {
		return nil, dialErr
	}
	return &nowherePacketConn{conn: udpConn, addr: destination.UDPAddr()}, nil
}

func (o *Outbound) Close() error {
	o.client.close()
	return nil
}

// ── nowhereClient ──────────────────────────────────────────────────────────

func (c *nowhereClient) getSession() (*nowhereTransport.Session, error) {
	if c.session != nil && !c.session.IsClosed() {
		return c.session, nil
	}
	s, err := nowhereTransport.NewSession(c.cfg)
	if err != nil {
		return nil, err
	}
	s.OnClose = func() {
		if c.session == s {
			c.session = nil
		}
	}
	c.session = s
	return s, nil
}

func (c *nowhereClient) close() {
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
}

// ── nowherePacketConn ──────────────────────────────────────────────────────

type nowherePacketConn struct {
	conn *nowhereTransport.UDPConn
	addr net.Addr
}

func (c *nowherePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	payload, err := c.conn.ReadPayload()
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, payload)
	return n, c.addr, nil
}

func (c *nowherePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if err := c.conn.WritePayload(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *nowherePacketConn) Close() error                       { return c.conn.Close() }
func (c *nowherePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *nowherePacketConn) SetDeadline(_ interface{}) error    { return nil }
func (c *nowherePacketConn) SetReadDeadline(_ interface{}) error  { return nil }
func (c *nowherePacketConn) SetWriteDeadline(_ interface{}) error { return nil }
