package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Listen               string
	TCPDialContext       func(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error)
	UDPDialContext       func(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error)
	TrafficEventConsumer func(e *TrafficEvent)
}

type Socks5Server struct {
	opts             Options
	trafficEventChan chan *TrafficEvent
}

func NewSocks5Server(opts Options) *Socks5Server {
	return &Socks5Server{
		opts:             opts,
		trafficEventChan: make(chan *TrafficEvent, 4096),
	}
}

func (s *Socks5Server) Run() error {
	l, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	go s.startTrafficEventConsumeDaemon()
	logrus.Infof("listen on %s for socks5 now", s.opts.Listen)
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			ctx := context.WithValue(context.Background(), spec.AppAddr, conn.RemoteAddr().String())
			dialerName, remoteAddr, netConn, udpConn := s.handshake(ctx, conn)
			var c1, c2 net.Conn
			var network string
			if udpConn == nil {
				c1, c2 = conn, netConn
				network = "tcp"
			} else {
				c1, c2 = udpConn, netConn
				network = "udp"
			}
			lbc, rbc := s.pipe(c1, c2)
			s.trafficEventChan <- &TrafficEvent{
				DialerName: dialerName,
				Network:    network,
				LocalAddr:  conn.RemoteAddr().String(),
				RemoteAddr: remoteAddr,
				In:         lbc,
				Out:        rbc,
			}
		}()
	}
}

func (s *Socks5Server) handshake(ctx context.Context, conn net.Conn) (dialerName, remoteAddr string, netConn, udpConn net.Conn) {
	log := logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr))
	buf := make([]byte, 1024)
	defer func() {
		if netConn == nil {
			conn.Close()
		}
	}()

	// auth
	n, err := conn.Read(buf[:2])
	if err != nil || n != 2 {
		log.Debug("invalid auth packet format @1")
		return
	}

	if buf[0] != 5 {
		conn.Read(buf[2:3])
		if string(buf[:3]) == "GET" {
			s.serveTemporaryHTTPServer(conn)
			return
		}
		log.Debug("unsupport socks version, closed")
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

	remoteAddr = fmt.Sprintf("%s:%d", addr, port)
	switch cmd {
	// 1. CONNECT
	case 1:
		dialerName, netConn, err = s.opts.TCPDialContext(ctx, remoteAddr)
		if err != nil {
			log.Errorf("socks5 establishing tcp://%s error: %s", remoteAddr, err)
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
		dialerName, netConn, err = s.opts.UDPDialContext(ctx, remoteAddr)
		if err != nil {
			log.Errorf("socks5 establishing udp://%s error: %s", remoteAddr, err)
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

func (s *Socks5Server) pipe(conn, rConn net.Conn) (lbc, rbc int64) {
	if conn == nil || rConn == nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbc, _ = io.Copy(conn, rConn)
		conn.Close()
	}()
	lbc, _ = io.Copy(rConn, conn)
	rConn.Close()
	wg.Wait()
	return
}

func (s *Socks5Server) serveTemporaryHTTPServer(conn net.Conn) {
	listenAddr := strings.Split(s.opts.Listen, ":")
	pacScriptServer := s.opts.Listen
	if listenAddr[0] == "0.0.0.0" || listenAddr[0] == "" {
		pacScriptServer = fmt.Sprintf("127.0.0.1:%s", listenAddr[1])
	}
	content := fmt.Sprintf("// give me a star please: https://github.com/rkonfj/toh\n\n"+
		"function FindProxyForURL(url, host) {\n"+
		"    if (isPlainHostName(host)) return 'DIRECT'\n"+
		"    if (isInNet(host, '10.0.0.0', '255.0.0.0') ||\n"+
		"    isInNet(host, '172.16.0.0', '255.240.0.0') ||\n"+
		"    isInNet(host, '192.168.0.0', '255.255.0.0') ||\n"+
		"    isInNet(host, '127.0.0.0', '255.255.255.0')) return 'DIRECT'\n"+
		"    return 'SOCKS5 %s'\n}\n", pacScriptServer)
	respHTTP(conn, content)
	for {
		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if strings.HasPrefix(line, "GET ") {
			respHTTP(conn, content)
		}
	}
}

func respHTTP(conn net.Conn, content string) {
	conn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "))
	conn.Write([]byte(strconv.Itoa(len(content))))
	conn.Write([]byte("\r\n\r\n"))
	conn.Write([]byte(content))
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
