package nowhere

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
)

// Conn implements net.Conn for a TCP stream proxied over Nowhere QUIC.
type Conn struct {
	mu      sync.Mutex
	session *Session
	stream  quic.Stream
	closed  bool
}

// NewConn dials a TCP connection to target through session.
func NewConn(session *Session, target string) (net.Conn, error) {
	stream, err := session.OpenTCPStream()
	if err != nil {
		return nil, err
	}
	header, err := EncodeTCPRequest(target)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if _, err := stream.Write(header); err != nil {
		stream.Close()
		return nil, fmt.Errorf("nowhere: write TCP header: %w", err)
	}
	c := &Conn{session: session, stream: stream}
	session.RegisterTCPConn(stream.StreamID(), c)
	return c, nil
}

func (c *Conn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *Conn) Write(b []byte) (int, error) { return c.stream.Write(b) }

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sid := c.stream.StreamID()
	c.mu.Unlock()
	err := c.stream.Close()
	c.session.ReleaseTCPStream(sid)
	return err
}

func (c *Conn) closeWithError(_ error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
}

func (c *Conn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *Conn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *Conn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
