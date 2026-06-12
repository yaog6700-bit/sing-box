package nowhere

import (
	"net"
	"sync"
)

// UDPConn implements a UDP flow over QUIC DATAGRAM.
type UDPConn struct {
	mu       sync.Mutex
	session  *Session
	flowID   uint64
	target   string
	closed   bool
	incoming chan []byte
}

// NewUDPConn registers a UDP flow in the session.
func NewUDPConn(session *Session, target string) (*UDPConn, error) {
	c := &UDPConn{
		session:  session,
		target:   target,
		incoming: make(chan []byte, 64),
	}
	fid, err := session.RegisterUDPFlow(c)
	if err != nil {
		return nil, err
	}
	c.flowID = fid
	return c, nil
}

// WritePayload sends a UDP payload to the server.
func (c *UDPConn) WritePayload(payload []byte) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.mu.Unlock()
	data, err := EncodeUDPDatagram(UDPTypeRequest, c.flowID, c.target, payload)
	if err != nil {
		return err
	}
	return c.session.WriteDatagram(data)
}

// ReadPayload blocks until a UDP response arrives.
func (c *UDPConn) ReadPayload() ([]byte, error) {
	payload, ok := <-c.incoming
	if !ok {
		return nil, net.ErrClosed
	}
	return payload, nil
}

func (c *UDPConn) deliver(payload []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	select {
	case c.incoming <- payload:
	default:
	}
}

// Close closes the UDP flow.
func (c *UDPConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	fid := c.flowID
	c.mu.Unlock()
	close(c.incoming)
	c.session.ReleaseUDPFlow(fid)
	if data, err := EncodeUDPDatagram(UDPTypeClose, fid, c.target, nil); err == nil {
		_ = c.session.WriteDatagram(data)
	}
	return nil
}

func (c *UDPConn) closeWithError(_ error) { c.Close() } //nolint:errcheck
