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
			ctx := context.WithValue(context.Background(), spec.AppAddr, conn.RemoteAddr().String())
			tcpConn, udpConn := s.handshake(ctx, conn)
			if udpConn == nil {
				s.pipe(conn, tcpConn)
				return
			}
			s.pipe(tcpConn, udpConn)
		}()
	}
}

func (s *Socks5Server) handshake(ctx context.Context, conn net.Conn) (netConn, udpConn net.Conn) {
	log := logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr))
	buf := make([]byte, 1024)
	defer func() {
		if netConn == nil {
			conn.Close()
		}
	}()

	// auth
	n, err := conn.Read(buf[:2])
	if err != nil || n != 2 || buf[0] != 5 {
		log.Debug("invalid auth packet format @1")
		return
	}

	nMethods := buf[1]

	n, err = conn.Read(buf[:nMethods])
	if err != nil || n != int(nMethods) {
		log.Debug("invalid auth packet format @2")
		return
	}

	n, err = conn.Write([]byte{0x05, 0x00})
	if err != nil || n != 2 {
		log.Debug("invalid auth packet format @3")
		return
	}

	// handle command
	n, err = conn.Read(buf[:4])
	if err != nil || n != 4 || buf[0] != 5 {
		log.Debug("handle command error @1")
		return
	}

	cmd, atyp := buf[1], buf[3]

	var addr string
	switch atyp {
	case 1:
		n, err = conn.Read(buf[:4])
		if err != nil || n != 4 {
			log.Debug("handle command error @2")
			return
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3:
		n, err = conn.Read(buf[:1])
		if err != nil || n != 1 {
			log.Debug("handle command error @3")
			return
		}
		addrLen := buf[0]
		n, err = conn.Read(buf[:addrLen])
		if err != nil || n != int(addrLen) {
			log.Debug("handle command error @4")
			return
		}
		addr = string(buf[:addrLen])
	default:
		log.Debug("handle command error @5")
		return
	}

	n, err = conn.Read(buf[:2])
	if err != nil || n != 2 {
		log.Debug("handle command error @read-port")
		return
	}
	port := spec.BytesToUint16(buf[:2])

	fullAddr := fmt.Sprintf("%s:%d", addr, port)
	switch cmd {
	// 1. CONNECT
	case 1:
		netConn, err = s.opts.TCPDialer(ctx, fullAddr)
		if err != nil {
			log.Errorf("establishing tcp://%s error: %s", fullAddr, err)
			respHostUnreachable(conn)
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01})
		if netConn.LocalAddr() != nil {
			addrPort := netip.MustParseAddrPort(netConn.LocalAddr().String())
			ip := addrPort.Addr().As4()
			conn.Write(ip[:])
			conn.Write(spec.Uint16ToBytes(addrPort.Port()))
		} else {
			conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		}

		return
	// 2. UDP ASSOCIATE
	case 3:
		netConn, err = s.opts.UDPDialer(ctx, fullAddr)
		if err != nil {
			log.Errorf("establishing udp://%s error: %s", fullAddr, err)
			respHostUnreachable(conn)
			return
		}
		udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})
		if err != nil {
			log.Debug("handle command error @UDP listener")
			respGeneralErr(conn)
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01})
		addrPort := netip.MustParseAddrPort(udpConn.LocalAddr().String())
		ip := addrPort.Addr().As4()
		conn.Write(ip[:])
		conn.Write(spec.Uint16ToBytes(addrPort.Port()))
		return
	// 3. do not support BIND now
	default:
		log.Debug("do not support BIND now")
		respNotSupported(conn)
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

func respHostUnreachable(conn net.Conn) {
	conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func respGeneralErr(conn net.Conn) {
	conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func respNotSupported(conn net.Conn) {
	conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
