package socks5

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type HTTPProxyServer struct {
	opts       Options
	pipeEngine *spec.PipeEngine
}

type protocolDetectionConnWrapper struct {
	net.Conn
	b []byte
}

func (c *protocolDetectionConnWrapper) Read(b []byte) (n int, err error) {
	if c.b != nil {
		n = copy(b, c.b)
		if n < len(c.b) {
			c.b = c.b[n:]
		} else {
			c.b = nil
		}
		return
	}
	return c.Conn.Read(b)
}

func (s *HTTPProxyServer) handle(b []byte, originConn net.Conn) {
	conn := &protocolDetectionConnWrapper{Conn: originConn, b: b}
	closeConn := true
	defer func() {
		if closeConn {
			conn.Close()
		}
	}()

	reader := bufio.NewReader(conn)

	for {
		request, err := http.ReadRequest(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			logrus.Error(err)
			break
		}
		addr := request.Host
		host, port, err := net.SplitHostPort(request.Host)
		if err != nil {
			host = request.URL.Host
			port = "80"
			addr += ":80"
		}

		// pac script
		if ip := net.ParseIP(host); ip != nil &&
			(ip.IsLoopback() || (ip.IsPrivate() && port ==
				fmt.Sprintf("%d", s.opts.AdvertisePort))) {
			s.responsePacScript(conn)
			continue
		}

		ctx := context.WithValue(context.Background(), spec.AppAddr, conn.RemoteAddr().String())
		dialerName, httpConn, err := s.opts.TCPDialContext(ctx, addr)
		if err != nil {
			logrus.Error(err)
			continue
		}

		if request.Method == http.MethodConnect {
			// https_proxy
			_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			if err != nil {
				logrus.Error(err)
				continue
			}
			go s.pipeEngine.Pipe(dialerName, conn, httpConn)
			closeConn = false
			break
		}

		// http proxy
		buf := bytes.Buffer{}
		request.Header.Del("Proxy-Connection")
		err = request.Write(&buf)
		if err != nil {
			logrus.Error(err)
			continue
		}

		go s.pipeEngine.Pipe(dialerName, &protocolDetectionConnWrapper{Conn: conn, b: buf.Bytes()}, httpConn)
		closeConn = false
		break
	}
}

func (s *HTTPProxyServer) responsePacScript(w io.Writer) {
	pacScriptServer := fmt.Sprintf("%s:%d", s.opts.AdvertiseIP, s.opts.AdvertisePort)
	content := fmt.Sprintf("// give me a star please: https://github.com/rkonfj/toh\n\n"+
		"function FindProxyForURL(url, host) {\n"+
		"    if (isPlainHostName(host)) return 'DIRECT'\n"+
		"    if (isInNet(host, '10.0.0.0', '255.0.0.0') ||\n"+
		"    isInNet(host, '172.16.0.0', '255.240.0.0') ||\n"+
		"    isInNet(host, '192.168.0.0', '255.255.0.0') ||\n"+
		"    isInNet(host, '127.0.0.0', '255.255.255.0')) return 'DIRECT'\n"+
		"    return 'SOCKS5 %s'\n}\n", pacScriptServer)
	w.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: "))
	w.Write([]byte(strconv.Itoa(len(content))))
	w.Write([]byte("\r\n\r\n"))
	w.Write([]byte(content))
}
