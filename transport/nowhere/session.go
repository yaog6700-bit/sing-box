package nowhere

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
)

const idleCloseDelay = 60 * time.Second

type sessionState int

const (
	stateIdle sessionState = iota
	stateConnecting
	stateAuthenticating
	stateReady
	stateClosed
)

// Config holds parameters needed to connect to a Nowhere v1 server.
type Config struct {
	Host          string
	Port          uint16
	Key           string
	Spec          string
	ALPN          string
	TLSInsecure   bool
	TLSServerName string
}

// Session manages a single authenticated QUIC connection to a Nowhere v1 server.
type Session struct {
	mu            sync.Mutex
	state         sessionState
	cfg           *Config
	effectiveSpec *EffectiveSpec
	conn          *quic.Conn

	waiters    []chan error
	tcpConns   map[quic.StreamID]*Conn
	udpFlows   map[uint64]*UDPConn
	nextFlowID uint64
	idleTimer  *time.Timer
	OnClose    func()
}

// NewSession creates a new Session from config. Call EnsureReady to connect.
func NewSession(cfg *Config) (*Session, error) {
	ps, err := BuildEffectiveSpec(cfg.Key, cfg.Spec, cfg.ALPN)
	if err != nil {
		return nil, err
	}
	return &Session{
		cfg:           cfg,
		effectiveSpec: ps,
		tcpConns:      make(map[quic.StreamID]*Conn),
		udpFlows:      make(map[uint64]*UDPConn),
		nextFlowID:    1,
	}, nil
}

// EffectiveALPN returns the ALPN string being used for this session.
func (s *Session) EffectiveALPN() string {
	return s.effectiveSpec.EffectiveALPN
}

// EnsureReady ensures the session is authenticated, then calls fn with the result.
func (s *Session) EnsureReady(fn func(error)) {
	s.mu.Lock()
	switch s.state {
	case stateReady:
		s.mu.Unlock()
		fn(nil)
		return
	case stateClosed:
		s.mu.Unlock()
		fn(fmt.Errorf("nowhere: session closed"))
		return
	case stateConnecting, stateAuthenticating:
		ch := make(chan error, 1)
		s.waiters = append(s.waiters, ch)
		s.mu.Unlock()
		fn(<-ch)
		return
	}
	s.state = stateConnecting
	s.mu.Unlock()
	go s.connect(fn)
}

func (s *Session) connect(first func(error)) {
	serverName := s.cfg.TLSServerName
	if serverName == "" {
		serverName = s.cfg.Host
	}

	tlsCfg := &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{s.effectiveSpec.EffectiveALPN},
		InsecureSkipVerify: s.cfg.TLSInsecure, //nolint:gosec
	}

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 20 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		s.failAll(fmt.Errorf("nowhere: resolve %s: %w", addr, err))
		first(fmt.Errorf("nowhere: resolve %s: %w", addr, err))
		return
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		s.failAll(fmt.Errorf("nowhere: listen UDP: %w", err))
		first(fmt.Errorf("nowhere: listen UDP: %w", err))
		return
	}

	transport := &quic.Transport{Conn: udpConn}
	qconn, err := transport.Dial(context.Background(), udpAddr, tlsCfg, quicCfg)
	if err != nil {
		udpConn.Close()
		s.failAll(fmt.Errorf("nowhere: QUIC dial: %w", err))
		first(fmt.Errorf("nowhere: QUIC dial: %w", err))
		return
	}

	s.mu.Lock()
	s.conn = qconn
	s.state = stateAuthenticating
	s.mu.Unlock()

	go s.readDatagrams()

	if err := s.authenticate(); err != nil {
		s.failAll(err)
		first(err)
		return
	}

	s.mu.Lock()
	s.state = stateReady
	waiters := s.waiters
	s.waiters = nil
	s.mu.Unlock()

	first(nil)
	for _, ch := range waiters {
		ch <- nil
	}
	s.scheduleIdleClose()
}

func (s *Session) authenticate() error {
	stream, err := s.conn.OpenStream()
	if err != nil {
		return fmt.Errorf("nowhere: open auth stream: %w", err)
	}
	frame, err := MakeAuthFrame(s.cfg.Key, s.effectiveSpec)
	if err != nil {
		stream.Close()
		return err
	}
	if _, err := stream.Write(frame); err != nil {
		return fmt.Errorf("nowhere: write auth frame: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("nowhere: close auth stream: %w", err)
	}
	return nil
}

func (s *Session) readDatagrams() {
	for {
		data, err := s.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		msg := DecodeUDPDatagram(data)
		if msg == nil {
			continue
		}
		s.mu.Lock()
		flow := s.udpFlows[msg.FlowID]
		s.mu.Unlock()
		if flow != nil {
			flow.deliver(msg.Payload)
		}
	}
}

// OpenTCPStream opens a new QUIC bidirectional stream.
// OpenStream already returns *quic.Stream (pointer) in sagernet's fork.
func (s *Session) OpenTCPStream() (*quic.Stream, error) {
	s.mu.Lock()
	if s.state != stateReady {
		s.mu.Unlock()
		return nil, fmt.Errorf("nowhere: session not ready")
	}
	conn := s.conn
	s.mu.Unlock()

	stream, err := conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("nowhere: open stream: %w", err)
	}

	s.mu.Lock()
	s.tcpConns[stream.StreamID()] = nil
	s.mu.Unlock()
	s.cancelIdleTimer()
	return stream, nil
}

// RegisterTCPConn links a Conn to its stream ID.
func (s *Session) RegisterTCPConn(id quic.StreamID, c *Conn) {
	s.mu.Lock()
	s.tcpConns[id] = c
	s.mu.Unlock()
}

// ReleaseTCPStream removes a stream and may schedule idle-close.
func (s *Session) ReleaseTCPStream(id quic.StreamID) {
	s.mu.Lock()
	delete(s.tcpConns, id)
	s.mu.Unlock()
	s.scheduleIdleClose()
}

// RegisterUDPFlow assigns a flow ID and registers the UDP connection.
func (s *Session) RegisterUDPFlow(c *UDPConn) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateReady {
		return 0, fmt.Errorf("nowhere: session not ready")
	}
	id := s.nextFlowID
	for id == 0 || s.udpFlows[id] != nil {
		id++
	}
	s.nextFlowID = id + 1
	s.udpFlows[id] = c
	return id, nil
}

// ReleaseUDPFlow removes a UDP flow.
func (s *Session) ReleaseUDPFlow(id uint64) {
	s.mu.Lock()
	delete(s.udpFlows, id)
	s.mu.Unlock()
	s.scheduleIdleClose()
}

// WriteDatagram sends a raw QUIC datagram.
func (s *Session) WriteDatagram(data []byte) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("nowhere: not connected")
	}
	return conn.SendDatagram(data)
}

// Close shuts down the session.
func (s *Session) Close() {
	s.mu.Lock()
	if s.state == stateClosed {
		s.mu.Unlock()
		return
	}
	s.state = stateClosed
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	conn := s.conn
	tcp := s.tcpConns
	udp := s.udpFlows
	s.tcpConns = make(map[quic.StreamID]*Conn)
	s.udpFlows = make(map[uint64]*UDPConn)
	s.mu.Unlock()

	if conn != nil {
		conn.CloseWithError(0, "closed")
	}
	closeErr := fmt.Errorf("nowhere: session closed")
	for _, c := range tcp {
		if c != nil {
			c.closeWithError(closeErr)
		}
	}
	for _, u := range udp {
		u.closeWithError(closeErr)
	}
	if s.OnClose != nil {
		s.OnClose()
	}
}

// IsClosed reports whether the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == stateClosed
}

func (s *Session) failAll(err error) {
	s.mu.Lock()
	waiters := s.waiters
	s.waiters = nil
	s.state = stateClosed
	s.mu.Unlock()
	for _, ch := range waiters {
		ch <- err
	}
	if s.OnClose != nil {
		s.OnClose()
	}
}

func (s *Session) scheduleIdleClose() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateReady || len(s.tcpConns)+len(s.udpFlows) > 0 {
		return
	}
	if s.idleTimer == nil {
		s.idleTimer = time.AfterFunc(idleCloseDelay, func() {
			s.mu.Lock()
			idle := len(s.tcpConns)+len(s.udpFlows) == 0
			s.mu.Unlock()
			if idle {
				s.Close()
			}
		})
	}
}

func (s *Session) cancelIdleTimer() {
	s.mu.Lock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.mu.Unlock()
}
