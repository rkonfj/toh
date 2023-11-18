package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/miekg/dns"
	D "github.com/rkonfj/toh/dns"
	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type TohClient struct {
	options          Options
	directNetDial    func(ctx context.Context, network, addr string) (conn net.Conn, err error)
	directHttpClient *http.Client
	serverIPv4s      []net.IP
	serverIPv6s      []net.IP
	serverPort       string
	dnsClient        *dns.Client
	proxyDNSResolver *D.Resolver
	conntrack        *Conntrack
}

type Options struct {
	Server, Key string
	Keepalive   time.Duration
	Headers     http.Header
}

func NewTohClient(options Options) (*TohClient, error) {
	if _, err := url.ParseRequestURI(options.Server); err != nil {
		return nil, fmt.Errorf("invalid server addr, %s", err.Error())
	}
	c := &TohClient{
		options:   options,
		dnsClient: &dns.Client{},
		conntrack: NewConntrack(),
	}
	c.proxyDNSResolver = &D.Resolver{
		IPv4Servers: D.DefaultResolver.IPv4Servers,
		IPv6Servers: D.DefaultResolver.IPv6Servers,
		Exchange:    c.dnsExchange,
	}
	c.directNetDial = func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		if len(c.serverIPv6s) == 0 && len(c.serverIPv4s) == 0 {
			var host string
			host, c.serverPort, err = net.SplitHostPort(addr)
			if err != nil {
				return
			}

			ipv4Ok := make(chan struct{})
			ipv6Ok := make(chan struct{})
			go func() {
				c.serverIPv6s, err = D.LookupIP6(host)
				if err != nil {
					logrus.Debugf("lookup6 for %s: %s", host, err)
					time.AfterFunc(5*time.Second, func() { close(ipv6Ok) })
					return
				}
				if len(c.serverIPv6s) > 0 {
					ipv6Ok <- struct{}{}
				}
			}()
			go func() {
				c.serverIPv4s, err = D.LookupIP4(host)
				if err != nil {
					logrus.Debugf("lookup4 for %s: %s", host, err)
					time.AfterFunc(5*time.Second, func() { close(ipv4Ok) })
					return
				}
				if len(c.serverIPv4s) > 0 {
					ipv4Ok <- struct{}{}
				}
			}()
			select {
			case <-ipv4Ok:
			case <-ipv6Ok:
			}
		}
		for _, addr := range c.serverIPv6s { // ipv6 first
			conn, err = (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addr.String(), c.serverPort))
			if err == nil {
				return
			}
		}
		for _, addr := range c.serverIPv4s { // fallback to ipv4
			conn, err = (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addr.String(), c.serverPort))
			if err == nil {
				return
			}
		}
		if err == nil {
			err = spec.ErrDNSRecordNotFound
		}
		return
	}
	c.directHttpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: c.directNetDial,
		},
	}
	return c, nil
}

func (c *TohClient) DNSExchange(dnServer string, query *dns.Msg) (resp *dns.Msg, err error) {
	return c.dnsExchange(dnServer, query)
}

// LookupIP lookup ipv4 and ipv6
func (c *TohClient) LookupIP(host string) (ips []net.IP, err error) {
	var wg sync.WaitGroup
	wg.Add(1)
	var e4, e6 error
	var ip6 []net.IP
	go func() {
		defer wg.Done()
		_ips, e6 := c.LookupIP6(host)
		if e6 == nil {
			ip6 = append(ip6, _ips...)
		}
	}()
	_ips, e4 := c.LookupIP4(host)
	if e4 == nil {
		ips = append(ips, _ips...)
	}
	wg.Wait()
	ips = append(ips, ip6...)
	if e4 != nil && e6 != nil {
		err = fmt.Errorf("%s %s", e4.Error(), e6.Error())
	}
	return
}

// LookupIP4 lookup only ipv4
func (c *TohClient) LookupIP4(host string) (ips []net.IP, err error) {
	return c.proxyDNSResolver.LookupIP(host, dns.TypeA)
}

// LookupIP4 lookup only ipv6
func (c *TohClient) LookupIP6(host string) (ips []net.IP, err error) {
	return c.proxyDNSResolver.LookupIP(host, dns.TypeAAAA)
}

func (c *TohClient) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return c.DialContext(ctx, "tcp", addr)
}

func (c *TohClient) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return c.DialContext(ctx, "udp", addr)
}

func (c *TohClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, addr, err := c.dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return spec.NewConn(conn, addr), nil
	case "udp", "udp4", "udp6":
		conn, addr, err := c.dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &spec.PacketConnWrapper{Conn: spec.NewConn(conn, addr)}, nil
	default:
		return nil, errors.New("unsupport network " + network)
	}
}
func (c *TohClient) Stats() (s *api.Stats, err error) {
	u, _ := url.ParseRequestURI(c.options.Server)
	scheme := u.Scheme
	if u.Scheme == "ws" {
		scheme = "http"
	} else if u.Scheme == "wss" {
		scheme = "https"
	}
	apiUrl := fmt.Sprintf("%s://%s/stats", scheme, u.Host)
	req, err := http.NewRequest(http.MethodGet, apiUrl, nil)
	req.Header.Add(spec.HeaderHandshakeKey, c.options.Key)
	resp, err := c.directHttpClient.Do(req)
	if err != nil {
		return
	}
	s = &api.Stats{}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(s)
	return
}

func (c *TohClient) Conntrack() *Conntrack {
	return c.conntrack
}

func (c *TohClient) dnsExchange(dnServer string, query *dns.Msg) (resp *dns.Msg, err error) {
	dnsLookupCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, _err := c.DialUDP(dnsLookupCtx, dnServer)
	if _err != nil {
		err = fmt.Errorf("dial error: %s", _err.Error())
		return
	}
	defer conn.Close()
	resp, _, err = c.dnsClient.ExchangeWithConn(query, &dns.Conn{Conn: &spec.PacketConnWrapper{Conn: conn}})
	return
}

func (c *TohClient) dial(ctx context.Context, network, addr string) (
	conn spec.StreamConn, remoteAddr net.Addr, err error) {
	handshake := http.Header{}
	handshake.Add(spec.HeaderHandshakeKey, c.options.Key)
	handshake.Add(spec.HeaderHandshakeNet, network)
	handshake.Add(spec.HeaderHandshakeAddr, addr)
	handshake.Add(spec.HeaderHandshakeNonce, spec.NewNonce())
	for k, v := range c.options.Headers {
		for _, item := range v {
			handshake.Add(k, item)
		}
	}

	t1 := time.Now()

	conn, respHeader, err := c.dialWS(ctx, c.options.Server, handshake)
	if err != nil {
		return
	}
	logrus.Debugf("%s://%s established successfully, toh latency %s", network, addr, time.Since(t1))

	estAddr := respHeader.Get(spec.HeaderEstablishAddr)
	if len(estAddr) == 0 {
		estAddr = "0.0.0.0:0"
	}
	host, _port, err := net.SplitHostPort(estAddr)
	port, _ := strconv.Atoi(_port)
	switch network {
	case "tcp", "tcp4", "tcp6":
		remoteAddr = &net.TCPAddr{
			IP:   net.ParseIP(host),
			Port: port,
		}
	case "udp", "udp4", "udp6":
		remoteAddr = &net.UDPAddr{
			IP:   net.ParseIP(host),
			Port: port,
		}
	default:
		err = spec.ErrUnsupportNetwork
	}
	conn.(*wsConn).entry.RemoteAddr = remoteAddr.String()
	conn.(*wsConn).entry.RemoteHost = addr
	conn.(*wsConn).entry.Proto = network
	go conn.(*wsConn).runPingLoop()
	return
}

func (c *TohClient) dialWS(ctx context.Context, urlstr string, header http.Header) (
	wsc *wsConn, respHeader http.Header, err error) {
	respHeader = http.Header{}
	var statusCode int
	dialer := ws.Dialer{
		NetDial: c.directNetDial,
		Header:  ws.HandshakeHeaderHTTP(header),
		OnHeader: func(key, value []byte) (err error) {
			respHeader.Add(string(key), string(value))
			return
		},
		OnStatusError: func(status int, reason []byte, resp io.Reader) {
			statusCode = status
		},
	}
	u, err := url.Parse(urlstr)
	if err != nil {
		return
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	conn, _, _, err := dialer.Dial(context.Background(), u.String())
	if statusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	if err != nil {
		err = fmt.Errorf("dial %s: %s", u, err)
		return
	}
	wsc = &wsConn{
		conn:            conn,
		keepalive:       c.options.Keepalive,
		connIdleTimeout: 75 * time.Second,
		entry: &ConnEntry{
			// Use the nonce returned by the server (some older versions of servers do not support nonce)
			Nonce:      spec.MustParseNonce(respHeader.Get(spec.HeaderHandshakeNonce)),
			LocalAddr:  conn.LocalAddr().String(),
			lastRWTime: time.Now(),
			ct:         c.conntrack,
		},
	}
	wsc.entry.add()
	return
}

type wsConn struct {
	conn            net.Conn
	keepalive       time.Duration
	connIdleTimeout time.Duration
	entry           *ConnEntry
}

func (c *wsConn) Read(ctx context.Context) (b []byte, err error) {
	c.entry.lastRWTime = time.Now()
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetReadDeadline(dl)
	}
	b, err = wsutil.ReadServerBinary(c.conn)
	if err != nil {
		return
	}
	for i, v := range b {
		b[i] = v ^ c.entry.Nonce
	}
	return
}
func (c *wsConn) Write(ctx context.Context, p []byte) error {
	c.entry.lastRWTime = time.Now()
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetWriteDeadline(dl)
	}
	for i, v := range p {
		p[i] = v ^ c.entry.Nonce
	}
	return wsutil.WriteClientBinary(c.conn, p)
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsConn) Close(code int, reason string) error {
	ws.WriteFrame(c.conn, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusCode(code), reason)))
	c.entry.remove()
	return c.conn.Close()
}

func (c *wsConn) Ping() error {
	return wsutil.WriteClientMessage(c.conn, ws.OpPing, ws.NewPingFrame([]byte{}).Payload)
}

// runPingLoop keepalive the websocket connection
func (c *wsConn) runPingLoop() {
	if c.keepalive == 0 {
		return
	}
	for {
		time.Sleep(c.keepalive)
		if time.Since(c.entry.lastRWTime) > c.connIdleTimeout {
			logrus.Debug("ping: exited. connection reached the max idle time ", c.connIdleTimeout)
			break
		}
		err := c.Ping()
		if err != nil {
			logrus.Debug("ping: ", err)
			break
		}
	}
}
