package server

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohServer struct {
	options Options
	acl     *ACL
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
		options: options,
		acl:     acl,
	}, nil
}

func (s *TohServer) Run() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			logrus.Errorf("%v", err)
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

		dialer := net.Dialer{}
		netConn, err := dialer.DialContext(context.Background(), network, addr)
		if err != nil {
			conn.Close(websocket.StatusBadGateway, "remote error")
			logrus.Infof("%s -> %s://%s dial error %v", spec.RealIP(r), network, addr, err)
			return
		}
		go s.pipe(conn, netConn)
	})

	logrus.Infof("server listen %s now", s.options.Listen)
	err := http.ListenAndServe(s.options.Listen, nil)
	if err != nil {
		logrus.Error(err)
	}
}

func (s *TohServer) pipe(wsConn *websocket.Conn, netConn net.Conn) {
	go func() {
		io.Copy(netConn, RWWS(wsConn))
		logrus.Debugf("ws conn closed, close remote conn(%s) now", netConn.RemoteAddr().String())
		netConn.Close()
	}()
	io.Copy(RWWS(wsConn), netConn)
	logrus.Debugf("remote conn(%s) closed, close ws conn now", netConn.RemoteAddr().String())
	wsConn.Close(websocket.StatusBadGateway, "remote close")
}
