package server

import (
	"context"
	"io"
	"math"
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
	bufPool          *sync.Pool
}

type Options struct {
	Listen string
	ACL    string
	Buf    uint64
	Admin  string
}

func NewTohServer(options Options) (*TohServer, error) {
	acl, err := NewACL(options.ACL, options.Admin)
	if err != nil {
		return nil, err
	}
	return &TohServer{
		options:          options,
		acl:              acl,
		trafficEventChan: make(chan *TrafficEvent, 2048),
		bufPool: &sync.Pool{New: func() any {
			buf := make([]byte, int(math.Max(float64(options.Buf), 512)))
			return &buf
		}},
	}, nil
}

func (s *TohServer) Run() {
	s.startTrafficEventConsumeDaemon()
	s.registerAdminAPIIfEnabled()

	http.HandleFunc("/stats", s.HandleShowStats)
	http.HandleFunc("/", s.HandleUpgradeWebSocket)

	logrus.Infof("server listen on %s now", s.options.Listen)
	err := http.ListenAndServe(s.options.Listen, nil)
	if err != nil {
		logrus.Error(err)
	}
}

func (s TohServer) HandleUpgradeWebSocket(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get(spec.HeaderHandshakeKey)
	network := r.Header.Get(spec.HeaderHandshakeNet)
	addr := r.Header.Get(spec.HeaderHandshakeAddr)
	clientIP := spec.RealIP(r)

	if err := s.acl.Check(key, network, addr); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		logrus.Infof("%s -> %s://%s %s", clientIP, network, addr, err.Error())
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
			Key:        key,
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
		buf := s.bufPool.Get().(*[]byte)
		defer s.bufPool.Put(buf)
		lbc, _ = io.CopyBuffer(netConn, RWWS(wsConn), *buf)
		logrus.Debugf("ws conn closed, close remote conn(%s) now", netConn.RemoteAddr().String())
		netConn.Close()
	}()
	buf := s.bufPool.Get().(*[]byte)
	defer s.bufPool.Put(buf)
	rbc, _ = io.CopyBuffer(RWWS(wsConn), netConn, *buf)
	logrus.Debugf("remote conn(%s) closed, close ws conn now", netConn.RemoteAddr().String())
	wsConn.Close(websocket.StatusBadGateway, "remote close")
	wg.Wait()
	return
}
