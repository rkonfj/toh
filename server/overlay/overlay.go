package overlay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/rkonfj/toh/server/id"
	"github.com/rkonfj/toh/spec"
	"github.com/rkonfj/toh/transport/ws"
	"github.com/sirupsen/logrus"
)

type streamConn struct {
	nonce     byte
	conn      *websocket.Conn
	net, addr string
}

func (s streamConn) Spec(onClose func()) spec.StreamConn {
	conn, setRemoteAddr := ws.NewStreamConn(s.conn, s.nonce)
	setRemoteAddr(s.net, s.addr)
	conn.(spec.StreamConnListener).SetOnClose(onClose)
	return conn
}

type Session struct {
	sig              chan streamConn
	network, address string
}

type Node struct {
	id       string
	key      string
	publicIP string
	router   *OverlayRouter
	control  *websocket.Conn
	mut      sync.Mutex
	sessions map[string]*Session
}

func (n *Node) AddRoute(net, address string) error {
	n.router.mut.Lock()
	defer n.router.mut.Unlock()
	if n.router.router[net] == nil {
		n.router.router[net] = make(map[string]*Node)
	}
	if _, ok := n.router.router[net][address]; ok {
		return errors.New("route already exists")
	}
	n.router.router[net][address] = n
	return nil
}

func (n *Node) RemoveRoute(net, address string) {
	n.router.mut.Lock()
	defer n.router.mut.Unlock()
	delete(n.router.router[net], address)
}

func (n *Node) DialContext(ctx context.Context, net, address string) (conn net.Conn, err error) {
	n.mut.Lock()
	sessionID := id.Generate(0)
	n.mut.Unlock()
	err = n.control.WriteJSON(ControlCommand{Action: "dial", Data: NetAddr{Net: net, Address: address, Session: sessionID}})
	if err != nil {
		return
	}
	n.mut.Lock()
	n.sessions[sessionID] = &Session{network: net, address: address, sig: make(chan streamConn)}
	n.mut.Unlock()

	cleanSessionResource := func() {
		n.mut.Lock()
		defer n.mut.Unlock()
		close(n.sessions[sessionID].sig)
		delete(n.sessions, sessionID)
	}

	// wait node to relay
	select {
	case <-ctx.Done():
		// clear session resources
		cleanSessionResource()
		return nil, ctx.Err()
	case streamConn := <-n.sessions[sessionID].sig:
		if strings.HasPrefix(net, "tcp") {
			return spec.NewConn(streamConn.Spec(cleanSessionResource)), nil
		}
		if strings.HasPrefix(net, "udp") {
			return spec.NewPacketConn(streamConn.Spec(cleanSessionResource)), nil
		}
		return nil, spec.ErrUnsupportNetwork
	}
}

func (n *Node) Relay(sessionID, nonce string, data *websocket.Conn) {
	n.mut.Lock()
	defer n.mut.Unlock()
	if session, ok := n.sessions[sessionID]; ok {
		session.sig <- streamConn{
			nonce: spec.MustParseNonce(nonce),
			conn:  data,
			net:   session.network,
			addr:  session.address,
		}
		return
	}
	data.Close()
}

func (n *Node) Close() error {
	n.control.Close()
	return nil
}

func (n *Node) Session(sessionID string) *Session {
	n.mut.Lock()
	defer n.mut.Unlock()
	return n.sessions[sessionID]
}

func (n *Node) ID() string {
	if len(n.publicIP) > 0 {
		return fmt.Sprintf("%s_%s", n.publicIP, n.id)
	}
	return n.control.RemoteAddr().String()
}

func (n *Node) runControlLoop() {
	for {
		mt, b, err := n.control.ReadMessage()
		if err != nil {
			n.router.UnregisterNode(n.key)
			n.control.Close()
			return
		}
		switch mt {
		case websocket.PingMessage:
			n.control.WriteMessage(websocket.PongMessage, nil)
		default:
			var cmd ControlCommand
			err = json.Unmarshal(b, &cmd)
			if err != nil {
				n.router.UnregisterNode(n.key)
				n.control.Close()
				return
			}
			logrus.WithField("node", n.key).Debugf("received command: %+v", cmd)
			switch cmd.Action {
			case "route":
				route := cmd.Data.(map[string]interface{})
				err = n.AddRoute(route["net"].(string), route["address"].(string))
				if err != nil {
					n.control.WriteJSON(ControlCommand{
						Action: "error",
						Data:   err.Error(),
					})
				}
			case "unroute":
				route := cmd.Data.(map[string]interface{})
				n.RemoveRoute(route["net"].(string), route["address"].(string))
			}
		}
	}
}

type OverlayRouter struct {
	mut            sync.RWMutex
	connectedNodes map[string]*Node
	router         map[string]map[string]*Node
}

func NewOverlayRouter() *OverlayRouter {
	return &OverlayRouter{
		connectedNodes: make(map[string]*Node),
		router:         make(map[string]map[string]*Node),
	}
}

func (r *OverlayRouter) RegisterNode(key, nodeIP string, wsConn *websocket.Conn) error {
	r.mut.Lock()
	defer r.mut.Unlock()
	if _, ok := r.connectedNodes[key]; ok {
		return errors.New("node already joined the overlay network")
	}
	logrus.WithField("node", key).Debug("overlay node connected")
	r.connectedNodes[key] = &Node{
		id:       id.Generate(0),
		key:      key,
		publicIP: nodeIP,
		router:   r,
		control:  wsConn,
		sessions: make(map[string]*Session),
	}
	go r.connectedNodes[key].runControlLoop()
	return nil
}

func (r *OverlayRouter) UnregisterNode(key string) {
	r.mut.Lock()
	defer r.mut.Unlock()
	logrus.WithField("node", key).Debug("overlay node exited")
	delete(r.connectedNodes, key)
	for _, m := range r.router {
		for k, n := range m {
			if n.key == key {
				delete(m, k)
			}
		}
	}
}

func (r *OverlayRouter) GetNode(key string) *Node {
	r.mut.RLock()
	defer r.mut.RUnlock()
	return r.connectedNodes[key]
}

// Nodes nodeIP -> routes
func (r *OverlayRouter) Nodes() map[string][]string {
	nodes := make(map[string][]string)
	for net, route := range r.router {
		for addr, node := range route {
			nodes[node.ID()] = append(nodes[node.ID()], fmt.Sprintf("%s/%s", addr, net))
		}
	}
	return nodes
}

func (r *OverlayRouter) RoutedNode(network, address string) (*Node, error) {
	r.mut.RLock()
	defer r.mut.RUnlock()
	var tryGroup []map[string]*Node
	switch network {
	case "tcp", "tcp4", "tcp6":
		tryGroup = append(tryGroup, r.router["tcp"], r.router["tcp4"], r.router["tcp6"])
	case "udp", "udp4", "udp6":
		tryGroup = append(tryGroup, r.router["udp"], r.router["udp4"], r.router["udp6"])
	default:
		return nil, spec.ErrUnsupportNetwork
	}
	var node *Node
	for _, router := range tryGroup {
		if router == nil {
			continue
		}
		if node = router[address]; node != nil {
			break
		}
	}
	if node == nil {
		return nil, errors.New("no route")
	}
	return node, nil
}

func (r *OverlayRouter) Shutdown() {
	r.mut.RLock()
	defer r.mut.RUnlock()
	for _, node := range r.connectedNodes {
		node.Close()
	}
}
