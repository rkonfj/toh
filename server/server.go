package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/rkonfj/toh/server/acl"
	"github.com/rkonfj/toh/server/admin"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type TohServer struct {
	adminAPI         *admin.AdminAPI
	acl              *acl.ACL
	trafficEventChan chan *TrafficEvent
	bufPool          *sync.Pool
	httpServer       *http.Server
}

type Options struct {
	Listen   string // http server listen address. required
	ACL      string // acl json file path. required
	Buf      uint64 // pipe buffer size, default is 1472. optional
	AdminKey string // admin api authenticate key. optional
}

func NewTohServer(options Options) (*TohServer, error) {
	acl, err := acl.NewACL(options.ACL, options.AdminKey)
	if err != nil {
		return nil, err
	}
	return &TohServer{
		httpServer:       &http.Server{Addr: options.Listen},
		acl:              acl,
		adminAPI:         &admin.AdminAPI{ACL: acl},
		trafficEventChan: make(chan *TrafficEvent, 2048),
		bufPool: &sync.Pool{New: func() any {
			buf := make([]byte, max(1472, options.Buf))
			return &buf
		}},
	}, nil
}

func (s *TohServer) Run() {
	go s.runTrafficEventConsumeLoop()
	go s.runShutdownListener()
	s.adminAPI.Register()

	http.HandleFunc("/stats", s.handleShowStats)
	http.HandleFunc("/", s.handleUpgradeWebSocket)

	logrus.Infof("server listen on %s now", s.httpServer.Addr)
	err := s.httpServer.ListenAndServe()
	if err != nil {
		logrus.Error(err)
	}
}

func (s *TohServer) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *TohServer) handleUpgradeWebSocket(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get(spec.HeaderHandshakeKey)
	network := r.Header.Get(spec.HeaderHandshakeNet)
	addr := r.Header.Get(spec.HeaderHandshakeAddr)
	clientIP := spec.RealIP(r)

	if err := s.acl.Check(key, network, addr); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		logrus.Infof("%s(%s) -> %s://%s: %s", clientIP, key, network, addr, err.Error())
		return
	}

	dialer := net.Dialer{}
	netConn, err := dialer.DialContext(context.Background(), network, addr)
	if err != nil {
		logrus.Debugf("%s(%s) -> %s://%s: %s", clientIP, key, network, addr, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	upgradeHeader := http.Header{}
	upgradeHeader.Add(spec.HeaderEstablishAddr, netConn.RemoteAddr().String())
	conn, _, _, err := ws.HTTPUpgrader{Header: upgradeHeader}.Upgrade(r, w)
	if err != nil {
		logrus.Error(err)
		return
	}

	go func() {
		lbc, rbc := s.pipe(spec.NewConn(&wsConn{conn: conn}, conn.RemoteAddr()), netConn)
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

func (s *TohServer) runShutdownListener() {
	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	s.acl.Shutdown()
	os.Exit(0)
}

type wsConn struct {
	conn net.Conn
}

func (c *wsConn) Read(ctx context.Context) (b []byte, err error) {
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetReadDeadline(dl)
	}
	return wsutil.ReadClientBinary(c.conn)
}
func (c *wsConn) Write(ctx context.Context, p []byte) error {
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetWriteDeadline(dl)
	}
	return wsutil.WriteServerBinary(c.conn, p)
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsConn) Close(code int, reason string) error {
	ws.WriteFrame(c.conn, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusCode(code), reason)))
	return c.conn.Close()
}
