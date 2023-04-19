package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohServer struct {
	proxyMap sync.Map
	options  Options
}

type Options struct {
	Listen string
}

func NewTohServer(options Options) *TohServer {
	return &TohServer{
		proxyMap: sync.Map{},
		options:  options,
	}
}

func (s *TohServer) Run() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			logrus.Errorf("websocket connected error: %v\n", err)
			return
		}
		go s.watchClient(conn)
	})

	logrus.Infof("server listen %s now\n", s.options.Listen)
	err := http.ListenAndServe(s.options.Listen, nil)
	if err != nil {
		logrus.Error(err)
	}
}

func (s *TohServer) sendPacketSegment(connId string, conn *websocket.Conn, b []byte) error {
	body := &bytes.Buffer{}
	body.Write([]byte(connId))
	body.Write([]byte{0x00})
	body.Write(b)
	return conn.Write(context.Background(), websocket.MessageBinary, body.Bytes())
}

func (s *TohServer) closeConn(connId string, conn *websocket.Conn) error {
	body := &bytes.Buffer{}
	body.Write([]byte(connId))
	body.Write([]byte{0x01})
	return conn.Write(context.Background(), websocket.MessageBinary, body.Bytes())
}

func (s *TohServer) getConn(connId string) (net.Conn, bool, error) {
	v, ok := s.proxyMap.Load(connId)
	if !ok {
		return nil, ok, nil
	}
	if conn, ok := v.(net.Conn); ok {
		return conn, ok, nil
	}
	return nil, false, errors.New("not net.Conn")
}

func (s *TohServer) watchClient(conn *websocket.Conn) {
	for {
		typ, b, err := conn.Read(context.Background())
		if err != nil {
			logrus.Errorf("websocket read error: %v\n", err)
			break
		}

		if typ != websocket.MessageBinary {
			logrus.Errorf("websocket msg type error: %s\n", typ)
			break
		}

		connId := string(b[:4])

		if b[4:5][0] == 1 {
			tcpConn, ok, _ := s.getConn(connId)
			if !ok {
				logrus.Errorf("proxy map non  conn: [%s]", connId)
				return
			}
			tcpConn.Close()
			s.proxyMap.Delete(connId)
			logrus.Debugf("client connection(%s) closed the remote(%s)",
				hex.EncodeToString([]byte(connId)), tcpConn.RemoteAddr().String())
			return
		}

		var addr netip.AddrPort
		if b[6:7][0] == 0 {
			addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[19:23])), spec.BytesToUint16(b[23:25]))
		} else {
			logrus.Error("not support ipv6")
			continue
		}

		var tcpConn net.Conn
		if _tcpConn, ok, _ := s.getConn(connId); ok {
			tcpConn = _tcpConn
		} else {
			dialer := net.Dialer{}
			_tcpConn, err := dialer.DialContext(context.Background(), "tcp", addr.String())
			if err != nil {
				panic(err)
			}
			tcpConn = _tcpConn
			s.proxyMap.Store(connId, tcpConn)
			go s.watchRemoteServer(connId, conn, tcpConn)
		}
		n, err := tcpConn.Write(b[25:])
		if err != nil {
			panic(err)
		}
		if n != len(b[25:]) {
			panic("write error")
		}
	}
}

func (s *TohServer) watchRemoteServer(connId string, conn *websocket.Conn, tcpConn net.Conn) {
	for {
		buf := make([]byte, 4096)
		n, err := tcpConn.Read(buf)
		if err != nil && err != io.EOF {
			logrus.Debugf("%s, %v", err)
			break
		}
		if err == io.EOF {
			logrus.Debugf("remote server(%s) closed the connection(%s)",
				tcpConn.RemoteAddr().String(), hex.EncodeToString([]byte(connId)))
			s.closeConn(connId, conn)
			break
		}
		s.sendPacketSegment(connId, conn, buf[:n])
	}
}
