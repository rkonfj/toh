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
	proxyMap sync.Map
	options  Options
	acl      *ACL
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
		proxyMap: sync.Map{},
		options:  options,
		acl:      acl,
	}, nil
}

func (s *TohServer) Run() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			logrus.Errorf("websocket connected error: %v\n", err)
			return
		}
		apiKey := r.Header.Get("x-toh-key")
		network := r.Header.Get("x-toh-net")
		addr := r.Header.Get("x-toh-addr")

		if !s.acl.Check(apiKey) {
			conn.Close(websocket.StatusPolicyViolation, "401")
			logrus.Infof("%s -> %s://%s auth failed", spec.RealIP(r), network, addr)
			return
		}

		if network == "tcp" {
			dialer := net.Dialer{}
			tcpConn, err := dialer.DialContext(context.Background(), "tcp", addr)
			if err != nil {
				panic(err)
			}
			go s.pipeTCP(conn, tcpConn)
			return
		}
		logrus.Error("unsupported network: ", network)
	})

	logrus.Infof("server listen %s now", s.options.Listen)
	err := http.ListenAndServe(s.options.Listen, nil)
	if err != nil {
		logrus.Error(err)
	}
}

func (s *TohServer) pipeTCP(wsConn *websocket.Conn, tcpConn net.Conn) {
	go func() {
		io.Copy(tcpConn, spec.RWWS(wsConn))
		tcpConn.Close()
	}()
	io.Copy(spec.RWWS(wsConn), tcpConn)
	wsConn.Close(websocket.StatusBadGateway, "remote close")
}
