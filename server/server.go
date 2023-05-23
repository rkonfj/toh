package server

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type TohServer struct {
	options          Options
	acl              *ACL
	trafficEventChan chan *TrafficEvent
	bufPool          *sync.Pool
}

type Options struct {
	Listen   string
	ACL      string
	Buf      uint64
	AdminKey string
}

func NewTohServer(options Options) (*TohServer, error) {
	acl, err := NewACL(options.ACL, options.AdminKey)
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
	go s.runTrafficEventConsumeLoop()
	go s.runShutdownListener()
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

	dialer := net.Dialer{}
	netConn, err := dialer.DialContext(context.Background(), network, addr)
	if err != nil {
		logrus.Infof("%s -> %s://%s dial error %v", clientIP, network, addr, err)
		return
	}
	w.Header().Add(spec.HeaderEstablishAddr, netConn.RemoteAddr().String())

	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		logrus.Error(err)
		return
	}

	go func() {
		lbc, rbc := s.pipe(spec.NewWSStreamConn(&wsConn{conn: conn}, conn.RemoteAddr()), netConn)
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

func (s *TohServer) pipe(wsConn *spec.WSStreamConn, netConn net.Conn) (lbc, rbc int64) {
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
