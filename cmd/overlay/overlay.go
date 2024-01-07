package overlay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rkonfj/toh/server/overlay"
	"github.com/rkonfj/toh/spec"
	"github.com/rkonfj/toh/transport/ws"
	"github.com/sirupsen/logrus"
)

type dataConn struct {
	*websocket.Conn
	nonce    byte
	sourceIP string
}

type Control struct {
	server            string
	key               string
	keepaliveDuration time.Duration
	controlConn       *websocket.Conn
	latencyT1         time.Time
	latency           time.Duration
}

func (c *Control) Route(net, address string) {
	if err := c.controlConn.WriteJSON(overlay.ControlCommand{
		Action: "route",
		Data:   overlay.NetAddr{Net: net, Address: address},
	}); err != nil {
		logrus.Errorf("route %s/%s failed: %s", address, net, err)
		return
	}
	logrus.Infof("route %s/%s", address, net)
}

func (c *Control) Run() error {
	go c.keepalive()
	for {
		var cmd overlay.ControlCommand
		err := c.controlConn.ReadJSON(&cmd)
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return nil
			}
			return err
		}
		switch cmd.Action {
		case "error":
			logrus.Error(cmd.Data)
		case "exit":
			logrus.Error(cmd.Data)
			c.Close()
			return nil
		case "connected":
			c.latency = time.Since(c.latencyT1)
			logrus.WithField("latency", c.latency).Info("started as an overlay node now")
		case "dial":
			c.dial(cmd.Data.(map[string]any)["net"].(string),
				cmd.Data.(map[string]any)["address"].(string), cmd.Data.(map[string]any)["session"].(string))
		}
	}
}

func (c *Control) Close() error {
	c.controlConn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second))
	return c.controlConn.Close()
}

func (c *Control) LocalAddr() net.Addr {
	return c.controlConn.LocalAddr()
}

func (c *Control) keepalive() {
	if c.keepaliveDuration == 0 {
		logrus.Debug("keepalive disabled")
		return
	}
	for {
		time.Sleep(max(c.keepaliveDuration, time.Second))
		c.latencyT1 = time.Now()
		err := c.controlConn.WriteMessage(websocket.PingMessage, nil)
		if err != nil {
			return
		}
	}
}

func (c *Control) connect(session string) (*dataConn, error) {
	handshakeHeader := http.Header{}
	handshakeHeader.Add(spec.HeaderHandshakeKey, c.key)
	handshakeHeader.Add(spec.HeaderOP, spec.OPOverlayData)
	handshakeHeader.Add(spec.HeaderSessionID, session)
	handshakeHeader.Add(spec.HeaderHandshakeNonce, spec.NewNonce())

	parsedServer, err := url.Parse(c.server)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server url: %w", err)
	}
	wsConn, httpResp, err := websocket.DefaultDialer.Dial(parsedServer.String(), handshakeHeader)
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode != http.StatusSwitchingProtocols {
		return nil, errors.New("handshake failed")
	}
	return &dataConn{
		Conn:     wsConn,
		nonce:    spec.MustParseNonce(httpResp.Header.Get(spec.HeaderHandshakeNonce)),
		sourceIP: httpResp.Header.Get(spec.HeaderSourceIP),
	}, nil
}

func (c *Control) dial(network, address, session string) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), network, address)
	if err != nil {
		c.controlConn.WriteJSON(overlay.ControlCommand{Action: "error", Data: err.Error()})
		return
	}
	transport, err := c.connect(session)
	if err != nil {
		c.controlConn.WriteJSON(overlay.ControlCommand{Action: "error", Data: err.Error()})
		return
	}
	streamConn, _ := ws.NewStreamConn(transport.Conn, transport.nonce)
	if keeper, ok := conn.(spec.StreamConnKeeper); ok {
		keeper.SetKeepalive(c.keepaliveDuration)
		go keeper.Keepalive()
	}
	if listener, ok := streamConn.(spec.StreamConnListener); ok {
		listener.SetOnClose(func() {
			logrus.WithField("net", network).WithField("source", "unknown").WithField("destination", address).Info("connection closed")
		})
	}
	logrus.WithField("net", network).WithField("source", "unknown").WithField("destination", address).Info("connection established")
	go c.pipe(spec.NewConn(streamConn), conn)
}

func (c *Control) pipe(wsConn *spec.Conn, netConn net.Conn) (lbc, rbc int64) {
	if wsConn == nil || netConn == nil {
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer netConn.Close()
		lbc, _ = io.Copy(netConn, wsConn)
		logrus.Debugf("ws conn closed, close remote conn(%s) now", netConn.RemoteAddr().String())
	}()
	defer wg.Wait()
	defer wsConn.Close()
	rbc, _ = io.Copy(wsConn, netConn)
	logrus.Debugf("remote conn(%s) closed, close ws conn now", netConn.RemoteAddr().String())
	return
}

type OverlayNetwork struct {
}

func (n *OverlayNetwork) Connect(server, key string, keepalive time.Duration) (*Control, error) {
	handshakeHeader := http.Header{}
	handshakeHeader.Add(spec.HeaderHandshakeKey, key)
	handshakeHeader.Add(spec.HeaderOP, spec.OPOverlayControl)

	parsedServer, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server url: %w", err)
	}
	t1 := time.Now()
	wsConn, httpResp, err := websocket.DefaultDialer.Dial(parsedServer.String(), handshakeHeader)
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode != http.StatusSwitchingProtocols {
		return nil, errors.New("handshake failed")
	}
	return &Control{controlConn: wsConn, server: server, key: key, keepaliveDuration: keepalive, latencyT1: t1}, nil
}
