package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rkonfj/toh/server/acl"
	"github.com/rkonfj/toh/server/admin"
	"github.com/rkonfj/toh/server/overlay"
	"github.com/rkonfj/toh/spec"
	"github.com/rkonfj/toh/transport/ws"
	"github.com/sirupsen/logrus"
)

type TohServer struct {
	adminAPI         *admin.AdminAPI
	acl              *acl.ACL
	trafficEventChan chan *TrafficEvent
	bufPool          *sync.Pool
	httpServer       *http.Server
	upgrader         *websocket.Upgrader
	overlayRouter    *overlay.OverlayRouter
}

type Options struct {
	Listen    string // http server listen address. required
	ACL       string // acl json file path. required
	Buf       uint64 // pipe buffer size, default is 1472. optional
	AdminKey  string // admin api authenticate key. optional
	DebugMode bool   // optional
}

func NewTohServer(options Options) (*TohServer, error) {
	acl, err := acl.NewACL(options.ACL, options.AdminKey)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	srv := TohServer{
		httpServer:       &http.Server{Addr: options.Listen, Handler: mux},
		upgrader:         &websocket.Upgrader{},
		acl:              acl,
		adminAPI:         &admin.AdminAPI{ACL: acl},
		overlayRouter:    overlay.NewOverlayRouter(),
		trafficEventChan: make(chan *TrafficEvent, 2048),
		bufPool: &sync.Pool{New: func() any {
			buf := make([]byte, max(1472, options.Buf))
			return &buf
		}},
	}

	srv.adminAPI.Register(mux)
	mux.HandleFunc("/stats", srv.handleShowStats)
	mux.HandleFunc("/", srv.handleMux)
	if options.DebugMode {
		srv.debugPprofRegister(mux)
	}

	return &srv, nil
}

func (s *TohServer) Run() {
	go s.runTrafficEventConsumeLoop()

	logrus.Infof("server listen on %s now", s.httpServer.Addr)
	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logrus.Error(err)
	}
}

func (s *TohServer) Shutdown(ctx context.Context) error {
	s.acl.Shutdown()
	s.overlayRouter.Shutdown()
	return s.httpServer.Shutdown(ctx)
}

func (s *TohServer) debugPprofRegister(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/debug/pprof/allocs", pprof.Handler("allocs").ServeHTTP)
	mux.HandleFunc("/debug/pprof/block", pprof.Handler("block").ServeHTTP)
	mux.HandleFunc("/debug/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
	mux.HandleFunc("/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)
	mux.HandleFunc("/debug/pprof/mutex", pprof.Handler("mutex").ServeHTTP)
	mux.HandleFunc("/debug/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
	logrus.Info("debug api(/debug/pprof/**) is enabled")
}

func (s *TohServer) handleMux(w http.ResponseWriter, r *http.Request) {
	op := r.Header.Get(spec.HeaderOP)
	switch op {
	case spec.OPOverlayControl:
		s.handleOverlay(w, r)
	case spec.OPOverlayData:
		s.handleOverlayTransport(w, r)
	default:
		s.handleTransportWs(w, r)
	}
}

// handleOverlay overlay network control
func (s *TohServer) handleOverlay(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get(spec.HeaderHandshakeKey)
	err := s.acl.CheckKey(key)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	wsConn, err := s.upgrader.Upgrade(w, r, http.Header{})
	if err != nil {
		logrus.Error(err)
		return
	}
	s.overlayRouter.RegisterNode(key, wsConn)
	wsConn.WriteJSON(overlay.ControlCommand{Action: "connected"})
}

// handleOverlayTransport overlay network data
func (s *TohServer) handleOverlayTransport(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get(spec.HeaderHandshakeKey)
	session := r.Header.Get(spec.HeaderSessionID)
	nonce := r.Header.Get(spec.HeaderHandshakeNonce)

	node := s.overlayRouter.GetNode(key)
	if node == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	upgradeHeader := http.Header{}
	upgradeHeader.Add(spec.HeaderHandshakeNonce, nonce) // nonce ack to client
	dataConn, err := s.upgrader.Upgrade(w, r, upgradeHeader)
	if err != nil {
		logrus.Error(err)
		return
	}
	node.Relay(session, nonce, dataConn)
}

// handleTransportWs handle client connection
func (s *TohServer) handleTransportWs(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get(spec.HeaderHandshakeKey)
	network := r.Header.Get(spec.HeaderHandshakeNet)
	addr := r.Header.Get(spec.HeaderHandshakeAddr)
	nonce := r.Header.Get(spec.HeaderHandshakeNonce)
	clientIP := spec.RealIP(r)

	if err := s.acl.Check(key, network, addr); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		logrus.Infof("%s(%s) -> %s://%s: %s", clientIP, key, network, addr, err.Error())
		return
	}

	var netDialer spec.NetDialer = &net.Dialer{}
	if node, err := s.overlayRouter.RoutedNode(network, addr); err == nil {
		netDialer = node
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	netConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		logrus.Debugf("%s(%s) -> %s://%s: %s", clientIP, key, network, addr, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	upgradeHeader := http.Header{}
	upgradeHeader.Add(spec.HeaderEstablishAddr, netConn.RemoteAddr().String()) // remote addr
	upgradeHeader.Add(spec.HeaderHandshakeNonce, nonce)                        // nonce ack to client
	conn, err := s.upgrader.Upgrade(w, r, upgradeHeader)
	if err != nil {
		logrus.Error(err)
		return
	}

	go func() {
		streamConn, _ := ws.NewStreamConn(conn, spec.MustParseNonce(nonce))
		lbc, rbc := s.pipe(spec.NewConn(streamConn), netConn)
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

func (s *TohServer) pipe(wsConn *spec.Conn, netConn net.Conn) (lbc, rbc int64) {
	if wsConn == nil || netConn == nil {
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer netConn.Close()
		buf := s.bufPool.Get().(*[]byte)
		defer s.bufPool.Put(buf)
		lbc, _ = io.CopyBuffer(netConn, wsConn, *buf)
		logrus.Debugf("ws conn closed, close remote conn(%s) now", netConn.RemoteAddr().String())
	}()
	defer wg.Wait()
	defer wsConn.Close()
	buf := s.bufPool.Get().(*[]byte)
	defer s.bufPool.Put(buf)
	rbc, _ = io.CopyBuffer(wsConn, netConn, *buf)
	logrus.Debugf("remote conn(%s) closed, close ws conn now", netConn.RemoteAddr().String())
	return
}
