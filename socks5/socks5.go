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
	TCPDialer func(ctx context.Context, addr string) (net.Conn, error)
	UDPDialer func(ctx context.Context, addr string) (net.Conn, error)
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
	logrus.Infof("listen on %s for socks5 now", s.opts.Listen)
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			buf := make([]byte, 1024)
			tcpConn, udpConn := s.handshake(conn, buf)
			if udpConn == nil {
				s.pipe(conn, tcpConn)
				return
			}
			s.pipe(tcpConn, udpConn)
		}()
	}
}

func (s *Socks5Server) handshake(conn net.Conn, buf []byte) (tcpConn, udpConn net.Conn) {
	defer func() {
		if tcpConn == nil {
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

	switch cmd {
	// 1. CONNECT
	case 1:
		tcpConn, err = s.opts.TCPDialer(context.Background(), fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			logrus.Debug("handle command error @CONNECT ", err)
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01})
		if tcpConn.LocalAddr() != nil {
			addrPort := netip.MustParseAddrPort(tcpConn.LocalAddr().String())
			ip := addrPort.Addr().As4()
			conn.Write(ip[:])
			conn.Write(spec.Uint16ToBytes(addrPort.Port()))
		} else {
			conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		}

		return
	// 2. UDP ASSOCIATE
	case 3:
		tcpConn, err = s.opts.UDPDialer(context.Background(), fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			logrus.Debug("handle command error @UDP ", err)
			return
		}
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})
		if err != nil {
			logrus.Debug("handle command error @UDP listener")
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01})
		addrPort := netip.MustParseAddrPort(udpConn.LocalAddr().String())
		ip := addrPort.Addr().As4()
		conn.Write(ip[:])
		conn.Write(spec.Uint16ToBytes(addrPort.Port()))
		return
	default:
		logrus.Debug("handle command error @unsupported")
		// 3. do not support BIND now
	}
	return
}

func (s *Socks5Server) pipe(conn, rConn net.Conn) {
	if conn == nil || rConn == nil {
		return
	}
	go func() {
		io.Copy(conn, rConn)
		conn.Close()
	}()
	io.Copy(rConn, conn)
	rConn.Close()
}
