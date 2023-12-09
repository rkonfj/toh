package ws

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type GorillaWsConn struct {
	conn            *websocket.Conn
	nonce           byte
	keepalive       time.Duration
	connIdleTimeout time.Duration
	lastRWTime      time.Time
	onClose         func()
	onReadWrite     func()
}

func (c *GorillaWsConn) Read() (b []byte, err error) {
	c.lastRWTime = time.Now()
	c.onReadWrite()
	mt, b, err := c.conn.ReadMessage()
	if err != nil {
		if websocket.IsUnexpectedCloseError(err,
			websocket.CloseGoingAway, websocket.CloseNormalClosure) {
			return nil, io.EOF
		}
		return
	}
	switch mt {
	case websocket.PingMessage:
		c.conn.WriteMessage(websocket.PongMessage, nil)
		return make([]byte, 0), nil
	case websocket.BinaryMessage:
	default:
		return make([]byte, 0), nil
	}
	for i, v := range b {
		b[i] = v ^ c.nonce
	}
	return
}
func (c *GorillaWsConn) Write(p []byte) error {
	c.lastRWTime = time.Now()
	c.onReadWrite()
	for i, v := range p {
		p[i] = v ^ c.nonce
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, p)
}

func (c *GorillaWsConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *GorillaWsConn) Close(code int, reason string) error {
	c.conn.WriteMessage(code, []byte(reason))
	c.onClose()
	return c.conn.Close()
}

func (c *GorillaWsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *GorillaWsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *GorillaWsConn) SetOnClose(onClose func()) {
	c.onClose = onClose
}

func (c *GorillaWsConn) SetOnReadWrite(onReadWrite func()) {
	c.onReadWrite = onReadWrite
}

func (c *GorillaWsConn) SetKeepalive(keepalive time.Duration) {
	c.keepalive = keepalive
}

func (c *GorillaWsConn) SetConnIdleTimeout(timeout time.Duration) {
	c.connIdleTimeout = timeout
}

// runPingLoop keepalive the websocket connection
func (c *GorillaWsConn) RunPingLoop() {
	if c.keepalive == 0 {
		return
	}
	for {
		time.Sleep(c.keepalive)
		if time.Since(c.lastRWTime) > c.connIdleTimeout {
			logrus.Debug("ping exited. connection reached the max idle time", c.connIdleTimeout)
			break
		}
		err := c.conn.WriteMessage(websocket.PingMessage, nil)
		if err != nil {
			logrus.Debug("ping exited.", err)
			break
		}
	}
}

func NewGorillaWsConn(conn *websocket.Conn, nonce byte) *GorillaWsConn {
	return &GorillaWsConn{
		conn: conn, nonce: nonce,
		onClose:     func() {},
		onReadWrite: func() {},
	}
}

func NewSpecConn(conn *websocket.Conn, nonce byte) *spec.Conn {
	return spec.NewConn(NewGorillaWsConn(conn, nonce), conn.RemoteAddr())
}
