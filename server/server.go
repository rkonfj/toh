package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohServer struct {
	options          Options
	acl              *ACL
	trafficEventChan chan *TrafficEvent
}

type Options struct {
	Listen string
	ACL    string
}

func NewTohServer(options Options) (*TohServer, error) {
	acl, err := NewACL(options.ACL)
	if err != nil {
		return nil, err
	}
	return &TohServer{
		options:          options,
		acl:              acl,
		trafficEventChan: make(chan *TrafficEvent, 4096),
	}, nil
}

func (s *TohServer) Run() {
	http.HandleFunc("/stats", s.HandleShowStats)
	http.HandleFunc("/", s.HandleUpgradeWebSocket)
	s.startTrafficEventConsumeDaemon()
	logrus.Infof("server listen on %s now", s.options.Listen)
	err := http.ListenAndServe(s.options.Listen, nil)
	if err != nil {
		logrus.Error(err)
	}
}

func (s TohServer) HandleUpgradeWebSocket(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(spec.HeaderHandshakeKey)
	network := r.Header.Get(spec.HeaderHandshakeNet)
	addr := r.Header.Get(spec.HeaderHandshakeAddr)
	clientIP := spec.RealIP(r)

	if err := s.acl.Check(apiKey); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		logrus.Infof("%s -> %s://%s auth failed: %s", clientIP, network, addr, err.Error())
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		logrus.Errorf("%v", err)
		return
	}
	dialer := net.Dialer{}
	netConn, err := dialer.DialContext(context.Background(), network, addr)
	if err != nil {
		conn.Close(websocket.StatusBadGateway, "remote error")
		logrus.Infof("%s -> %s://%s dial error %v", clientIP, network, addr, err)
		return
	}
	go func() {
		lbc, rbc := s.pipe(conn, netConn)
		s.trafficEventChan <- &TrafficEvent{
			In:         lbc,
			Out:        rbc,
			Key:        apiKey,
			Network:    network,
			ClientIP:   clientIP,
			RemoteAddr: addr,
		}
	}()
}

func (s *TohServer) pipe(wsConn *websocket.Conn, netConn net.Conn) (lbc, rbc int64) {
	if wsConn == nil || netConn == nil {
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		lbc, _ = io.Copy(netConn, RWWS(wsConn))
		logrus.Debugf("ws conn closed, close remote conn(%s) now", netConn.RemoteAddr().String())
		netConn.Close()
	}()
	rbc, _ = io.Copy(RWWS(wsConn), netConn)
	logrus.Debugf("remote conn(%s) closed, close ws conn now", netConn.RemoteAddr().String())
	wsConn.Close(websocket.StatusBadGateway, "remote close")
	wg.Wait()
	return
}
