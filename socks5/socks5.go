package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Listen    string
	TcpDialer func(ctx context.Context, addr string) (net.Conn, error)
}

type Socks5Server struct {
	opts Options
}

func NewSocks5Server(opts Options) *Socks5Server {
	return &Socks5Server{
		opts: opts,
	}
}

func (s *Socks5Server) Run() error {
	l, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	logrus.Infof("socks5 listen on %s now", s.opts.Listen)
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go func() {
			buf := make([]byte, 1024)
			rConn := s.handshake(conn, buf)
			if rConn != nil {
				s.pipe(conn, rConn)
			}
		}()
	}
}
func (s *Socks5Server) handshake(conn net.Conn, buf []byte) (rConn net.Conn) {
	defer func() {
		if rConn == nil {
			conn.Close()
		}
	}()
	// auth
	n, err := conn.Read(buf[:2])
	if err != nil || n != 2 || buf[0] != 5 {
		logrus.Debug("invalid auth packet format @1")
		return
	}

	nMethods := buf[1]

	n, err = conn.Read(buf[:nMethods])
	if err != nil || n != int(nMethods) {
		logrus.Debug("invalid auth packet format @2")
		return
	}

	n, err = conn.Write([]byte{0x05, 0x00})
	if err != nil || n != 2 {
		logrus.Debug("invalid auth packet format @3")
		return
	}

	// handle command
	n, err = conn.Read(buf[:4])
	if err != nil || n != 4 || buf[0] != 5 {
		logrus.Debug("handle command error @1")
		return
	}

	cmd, atyp := buf[1], buf[3]

	var addr string
	switch atyp {
	case 1:
		n, err = conn.Read(buf[:4])
		if err != nil || n != 4 {
			logrus.Debug("handle command error @2")
			return
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3:
		n, err = conn.Read(buf[:1])
		if err != nil || n != 1 {
			logrus.Debug("handle command error @3")
			return
		}
		addrLen := buf[0]
		n, err = conn.Read(buf[:addrLen])
		if err != nil || n != int(addrLen) {
			logrus.Debug("handle command error @4")
			return
		}
		addr = string(buf[:addrLen])
	default:
		logrus.Debug("handle command error @5")
		return
	}

	n, err = conn.Read(buf[:2])
	if err != nil || n != 2 {
		logrus.Debug("handle command error @read-port")
		return
	}

	port := spec.BytesToUint16(buf[:2])

	// 1. CONNECT
	if cmd == 1 {
		rConn, err := s.opts.TcpDialer(context.Background(), fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			logrus.Debug("handle command error @CONNECT ", err)
			return nil
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01})
		if rConn.LocalAddr() != nil {
			addrPort := netip.MustParseAddrPort(rConn.LocalAddr().String())
			ip := addrPort.Addr().As4()
			conn.Write(ip[:])
			conn.Write(spec.Uint16ToBytes(addrPort.Port()))
		} else {
			conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		}

		return rConn
	}
	logrus.Debug("handle command error @unsupported")
	// 2. do not support BIND and UDP ASSOCIATE now
	return nil
}

func (s *Socks5Server) pipe(conn, rConn net.Conn) {
	logrus.Debugf("strat pipeline %s<->%s", conn.RemoteAddr().String(), rConn.RemoteAddr().String())
	go func() {
		io.Copy(conn, rConn)
		conn.Close()
	}()
	io.Copy(rConn, conn)
	rConn.Close()
}
