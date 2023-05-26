package spec

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// TohClient the ToH client
type TohClient interface {
	DialTCP(ctx context.Context, address string) (net.Conn, error)
	DialUDP(ctx context.Context, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	LookupIP(host string) (ips []net.IP, err error)
	LookupIP4(host string) (ips []net.IP, err error)
	LookupIP6(host string) (ips []net.IP, err error)
}

// WSConn websocket connection which used to read, write and close data
type WSConn interface {
	Read(ctx context.Context) ([]byte, error)
	Write(ctx context.Context, p []byte) error
	LocalAddr() net.Addr
	Close(code int, reason string) error
}

// WSStreamConn tcp/udp connection based on websocket connection
type WSStreamConn struct {
	wsConn        WSConn
	addr          net.Addr
	readDeadline  *time.Time
	writeDeadline *time.Time
	buf           []byte
}

func NewWSStreamConn(wsConn WSConn, addr net.Addr) *WSStreamConn {
	return &WSStreamConn{
		wsConn: wsConn,
		addr:   addr,
	}
}

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (c *WSStreamConn) Read(b []byte) (n int, err error) {
	if c.buf != nil {
		n = copy(b, c.buf)
		if n < len(c.buf) {
			c.buf = c.buf[n:]
		} else {
			c.buf = nil
		}
		return
	}

	ctx := context.Background()
	if c.readDeadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.readDeadline)
		ctx = _ctx
		defer cancel()
	}

	wsb, err := c.wsConn.Read(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "StatusNormalClosure") ||
			strings.Contains(err.Error(), "1000") {
			return 0, io.EOF
		}
		return 0, err
	}

	n = copy(b, wsb)
	if n < len(wsb) {
		c.buf = wsb[n:]
	}
	return
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (c *WSStreamConn) Write(b []byte) (n int, err error) {
	ctx := context.Background()
	if c.writeDeadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.writeDeadline)
		ctx = _ctx
		defer cancel()
	}
	n = len(b)
	err = c.wsConn.Write(ctx, b)
	return
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *WSStreamConn) Close() error {
	return c.wsConn.Close(1000, "have read")
}

// LocalAddr returns the local network address, if known.
func (c *WSStreamConn) LocalAddr() net.Addr {
	return c.wsConn.LocalAddr()
}

// RemoteAddr returns the remote network address, if known.
func (c *WSStreamConn) RemoteAddr() net.Addr {
	return c.addr
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *WSStreamConn) SetDeadline(t time.Time) error {
	c.readDeadline = &t
	c.writeDeadline = &t
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *WSStreamConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = &t
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *WSStreamConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = &t
	return nil
}

// PacketConnWrapper wrap UDP conn
type PacketConnWrapper struct {
	net.Conn
	l sync.RWMutex
}

func (c *PacketConnWrapper) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.RemoteAddr().String() != addr.String() {
		return 0, errors.New("connection-oriented UDP does not allow write to another address")
	}
	c.l.Lock()
	defer c.l.Unlock()
	return c.Conn.Write(b)
}

func (c *PacketConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	c.l.Lock()
	defer c.l.Unlock()
	n, err := c.Conn.Read(b)
	return n, c.RemoteAddr(), err
}
