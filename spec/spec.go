package spec

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

// Tohc the toh client
type TohClient interface {
	DialTCP(ctx context.Context, address string) (net.Conn, error)
	DialUDP(ctx context.Context, address string) (net.PacketConn, error)
}

func NewWSTCPConn(wsConn *websocket.Conn, addr net.Addr) *WSTCPConn {
	return &WSTCPConn{
		wsConn: wsConn,
		addr:   addr,
	}
}

type WSTCPConn struct {
	wsConn        *websocket.Conn
	addr          net.Addr
	deadline      *time.Time
	readDeadline  *time.Time
	writeDeadline *time.Time
	buf           []byte
}

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (c *WSTCPConn) Read(b []byte) (n int, err error) {
	ctx := context.Background()
	if c.readDeadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.readDeadline)
		ctx = _ctx
		defer cancel()
	} else if c.deadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.deadline)
		ctx = _ctx
		defer cancel()
	}

	if len(c.buf) > 0 {
		if len(c.buf) <= len(b) {
			n := copy(b, c.buf)
			c.buf = nil
			return n, nil
		}
		copy(b, c.buf[:len(b)])
		c.buf = c.buf[len(b):]
		return len(b), nil
	}

	_, wsb, err := c.wsConn.Read(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "StatusBadGateway") {
			return 0, io.EOF
		}
		return 0, err
	}

	if len(wsb) > len(b) {
		copy(b, wsb[:len(b)])
		c.buf = make([]byte, len(wsb[len(b):]))
		copy(c.buf, wsb[len(b):])
		return len(b), nil
	}
	copy(b, wsb)
	return len(wsb), nil
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (c *WSTCPConn) Write(b []byte) (n int, err error) {
	ctx := context.Background()
	if c.writeDeadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.writeDeadline)
		ctx = _ctx
		defer cancel()
	} else if c.deadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.deadline)
		ctx = _ctx
		defer cancel()
	}
	err = c.wsConn.Write(ctx, websocket.MessageBinary, b)
	return
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *WSTCPConn) Close() error {
	return c.wsConn.Close(websocket.StatusNormalClosure, "have read")
}

// LocalAddr returns the local network address, if known.
func (c *WSTCPConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the remote network address, if known.
func (c *WSTCPConn) RemoteAddr() net.Addr {
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
func (c *WSTCPConn) SetDeadline(t time.Time) error {
	c.deadline = &t
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *WSTCPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = &t
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *WSTCPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = &t
	return nil
}

type WSReadWrite struct {
	ws  *websocket.Conn
	buf []byte
}

func RWWS(conn *websocket.Conn) *WSReadWrite {
	return &WSReadWrite{
		ws: conn,
	}
}

func (ws *WSReadWrite) Read(b []byte) (n int, err error) {
	if len(ws.buf) > 0 {
		if len(ws.buf) <= len(b) {
			copy(b, ws.buf)
			ws.buf = nil
			return len(ws.buf), nil
		}
		copy(b, ws.buf[:len(b)])
		ws.buf = ws.buf[len(b):]
		return len(b), nil
	}

	_, wsb, err := ws.ws.Read(context.Background())
	if err != nil {
		return len(wsb), err
	}

	if len(wsb) > len(b) {
		copy(b, wsb[:len(b)])
		ws.buf = make([]byte, len(wsb[len(b):]))
		copy(ws.buf, wsb[len(b):])
		return len(b), nil
	}
	copy(b, wsb)
	return len(wsb), nil
}

func (ws *WSReadWrite) Write(p []byte) (n int, err error) {
	err = ws.ws.Write(context.Background(), websocket.MessageBinary, p)
	return len(p), err
}
