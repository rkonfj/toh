package ws

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
	remoteAddr      net.Addr
}

func (c *GorillaWsConn) Read() (b []byte, err error) {
	c.lastRWTime = time.Now()
	c.onReadWrite()
	mt, b, err := c.conn.ReadMessage()
	if err != nil {
		if websocket.IsCloseError(err,
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

func (c *GorillaWsConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *GorillaWsConn) Close(code int, reason string) error {
	c.conn.WriteMessage(code, []byte(reason))
	c.onClose()
	return c.conn.Close()
}

func (c *GorillaWsConn) Nonce() byte {
	return c.nonce
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

// Keepalive keepalive the websocket connection
func (c *GorillaWsConn) Keepalive() {
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

func Connect(params spec.ConnectParameters, netDial spec.Dial) (spec.StreamConn, error) {
	dialer := websocket.Dialer{
		NetDialContext:   netDial,
		HandshakeTimeout: 15 * time.Second,
	}
	handshake := http.Header{}
	handshake.Add(spec.HeaderHandshakeKey, params.Key)
	handshake.Add(spec.HeaderHandshakeNet, params.Network)
	handshake.Add(spec.HeaderHandshakeAddr, params.Addr)
	handshake.Add(spec.HeaderHandshakeNonce, spec.NewNonce())
	for k, v := range params.Header {
		for _, item := range v {
			handshake.Add(k, item)
		}
	}

	t1 := time.Now()
	conn, httpResp, err := dialer.Dial(params.URL.String(), handshake)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %s", params.URL.String(), err)
	}
	if httpResp.StatusCode == http.StatusUnauthorized {
		return nil, spec.ErrAuth
	}
	logrus.Debugf("%s://%s established successfully, toh latency %s",
		params.Network, params.Addr, time.Since(t1))

	nonce := spec.MustParseNonce(httpResp.Header.Get(spec.HeaderHandshakeNonce))
	wsConn := GorillaWsConn{
		conn: conn, nonce: nonce,
		onClose:     func() {},
		onReadWrite: func() {},
	}
	wsConn.SetKeepalive(params.Keepalive)
	wsConn.SetConnIdleTimeout(75 * time.Second)

	establishAddr := httpResp.Header.Get(spec.HeaderEstablishAddr)
	if len(establishAddr) == 0 {
		establishAddr = "0.0.0.0:0"
	}
	if strings.HasPrefix(params.Network, "tcp") {
		wsConn.remoteAddr, err = net.ResolveTCPAddr(params.Network, establishAddr)
	} else if strings.HasPrefix(params.Network, "udp") {
		wsConn.remoteAddr, err = net.ResolveUDPAddr(params.Network, establishAddr)
	} else {
		err = spec.ErrUnsupportNetwork
	}
	if err != nil {
		return nil, err
	}
	return &wsConn, nil
}

func NewStreamConn(conn *websocket.Conn, nonce byte) spec.StreamConn {
	return &GorillaWsConn{
		conn: conn, nonce: nonce,
		onClose: func() {}, onReadWrite: func() {},
	}
}
