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
	"time"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type HTTPProxyServer struct {
	opts       Options
	pipeEngine *spec.PipeEngine
}

type Handler func(w http.ResponseWriter, r *http.Request)

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
			if h, ok := s.opts.HTTPHandlers[request.URL.Path]; ok {
				w := newResponseWriter(conn)
				h(w, request)
				err := w.write()
				if err != nil {
					logrus.Error(err)
				}
				continue
			}
			s.responsePacScript(conn, fmt.Sprintf("%s:%s", host, port))
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

		go s.pipeEngine.Pipe(dialerName,
			&protocolDetectionConnWrapper{Conn: conn, b: buf.Bytes()}, httpConn)
		closeConn = false
		break
	}
}

func (s *HTTPProxyServer) responsePacScript(w io.Writer, referAddr string) {
	pacScriptServer := referAddr
	if !net.ParseIP(s.opts.AdvertiseIP).IsLoopback() {
		pacScriptServer = fmt.Sprintf("%s:%d", s.opts.AdvertiseIP, s.opts.AdvertisePort)
	}
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

type HTTPResponseWriter struct {
	net.Conn
	headers    http.Header
	statusCode int
	body       bytes.Buffer
}

func newResponseWriter(conn net.Conn) *HTTPResponseWriter {
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	h.Set("Server", "ToH")

	return &HTTPResponseWriter{
		Conn:       conn,
		headers:    h,
		statusCode: http.StatusOK,
		body:       bytes.Buffer{},
	}
}

func (w *HTTPResponseWriter) Header() http.Header {
	return w.headers
}

func (w *HTTPResponseWriter) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

func (w *HTTPResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *HTTPResponseWriter) write() (err error) {
	b := w.body.Bytes()
	w.headers.Set("Content-Length", fmt.Sprintf("%d", len(b)))

	statusLine := fmt.Sprintf("HTTP/1.1 %d %s", w.statusCode, http.StatusText(w.statusCode))
	w.Conn.Write([]byte(statusLine + "\r\n"))
	w.headers.Write(w.Conn)
	w.Conn.Write([]byte("\r\n"))

	_, err = w.Conn.Write(b)
	return
}
