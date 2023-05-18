package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohClient struct {
	options    Options
	httpClient *http.Client
	dnsClient  *dns.Client
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
	}
	c.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return
				}

				ips, err := c.directLookupIP(host, dns.TypeA)
				if err == spec.ErrDNSTypeANotFound {
					ips, err = c.directLookupIP(host, dns.TypeAAAA)
				}
				if err != nil {
					return
				}
				return (&net.Dialer{}).DialContext(ctx, network,
					net.JoinHostPort(ips[rand.Intn(len(ips))].String(), port))
			},
		},
	}
	return c, nil
}

func (c *TohClient) DNSExchange(dnServer string, query *dns.Msg) (resp *dns.Msg, err error) {
	return c.dnsExchange(dnServer, query, false)
}

// LookupIP lookup ipv4 and ipv6
func (c *TohClient) LookupIP(host string) (ips []net.IP, err error) {
	var wg sync.WaitGroup
	wg.Add(1)
	var e4, e6 error
	go func() {
		defer wg.Done()
		_ips, e6 := c.LookupIP6(host)
		if e6 == nil {
			ips = append(ips, _ips...)
		}
	}()
	_ips, e4 := c.lookupIP(host, dns.TypeA, false)
	if e4 == nil {
		ips = append(ips, _ips...)
	}
	wg.Wait()
	if e4 != nil && e6 != nil {
		err = fmt.Errorf("%s %s", e4.Error(), e6.Error())
	}
	return
}

// LookupIP4 lookup only ipv4
func (c *TohClient) LookupIP4(host string) (ips []net.IP, err error) {
	return c.lookupIP(host, dns.TypeA, false)
}

// LookupIP4 lookup only ipv6
func (c *TohClient) LookupIP6(host string) (ips []net.IP, err error) {
	return c.lookupIP(host, dns.TypeAAAA, false)
}

func (c *TohClient) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return c.DialContext(ctx, "tcp", addr)
}

func (c *TohClient) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return c.DialContext(ctx, "udp", addr)
}

func (c *TohClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		conn, addr, err := c.dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return spec.NewWSStreamConn(conn, addr), nil
	default:
		return nil, errors.New("unsupport network")
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
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	s = &api.Stats{}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(s)
	return
}

func (c *TohClient) dnsExchange(dnServer string, query *dns.Msg, direct bool) (resp *dns.Msg, err error) {
	dnsLookupCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if direct {
		resp, _, err = c.dnsClient.ExchangeContext(dnsLookupCtx, query, dnServer)
	} else {
		conn, _err := c.DialUDP(dnsLookupCtx, dnServer)
		if _err != nil {
			err = fmt.Errorf("dial error: %s", _err.Error())
			return
		}

		defer conn.Close()
		resp, _, err = c.dnsClient.ExchangeWithConn(query, &dns.Conn{Conn: &spec.PacketConnWrapper{Conn: conn}})
	}
	return
}

func (c *TohClient) lookupIP(host string, t uint16, direct bool) (ips []net.IP, err error) {
	ip := net.ParseIP(host)
	if ip != nil {
		ips = append(ips, ip)
		return
	}
	query := &dns.Msg{}
	query.SetQuestion(dns.Fqdn(host), t)
	var resp *dns.Msg
	for _, dnServer := range []string{"8.8.8.8:53", "223.5.5.5:53"} {
		resp, err = c.dnsExchange(dnServer, query, direct)
		if err == nil {
			break
		}
	}
	if err != nil {
		return
	}
	for _, a := range resp.Answer {
		if a.Header().Rrtype == dns.TypeA {
			ips = append(ips, a.(*dns.A).A)
		}
		if a.Header().Rrtype == dns.TypeAAAA {
			ips = append(ips, a.(*dns.AAAA).AAAA)
		}
	}
	if len(ips) == 0 {
		if t == dns.TypeA {
			err = spec.ErrDNSTypeANotFound
		} else if t == dns.TypeAAAA {
			err = spec.ErrDNSTypeAAAANotFound
		} else {
			err = fmt.Errorf("resolve %s : no type %s was found", host, dns.Type(t))
		}
	}
	return
}

func (c *TohClient) directLookupIP(host string, t uint16) (ips []net.IP, err error) {
	return c.lookupIP(host, t, true)
}

func (c *TohClient) dial(ctx context.Context, network, addr string) (
	wsConn *nhooyrWSConn, remoteAddr net.Addr, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	ips, err := c.directLookupIP(host, dns.TypeA)
	if err == spec.ErrDNSTypeANotFound {
		ips, err = c.directLookupIP(host, dns.TypeAAAA)
	}
	if err != nil {
		return
	}

	_port, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		remoteAddr = &net.TCPAddr{
			IP:   ips[rand.Intn(len(ips))],
			Port: int(_port),
		}
	case "udp", "udp4", "udp6":
		remoteAddr = &net.UDPAddr{
			IP:   ips[rand.Intn(len(ips))],
			Port: int(_port),
		}
	default:
		err = spec.ErrUnsupportNetwork
		return
	}

	handshake := http.Header{}
	handshake.Add(spec.HeaderHandshakeKey, c.options.Key)
	handshake.Add(spec.HeaderHandshakeNet, network)
	handshake.Add(spec.HeaderHandshakeAddr, addr)
	for k, v := range c.options.Headers {
		for _, item := range v {
			handshake.Add(k, item)
		}
	}

	t1 := time.Now()
	conn, _, err := websocket.Dial(ctx, c.options.Server, &websocket.DialOptions{
		HTTPHeader: handshake, HTTPClient: c.httpClient,
	})
	if err != nil {
		if strings.Contains(err.Error(), "401") {
			err = spec.ErrAuth
			return
		}
		return
	}
	wsConn = newNhooyrWSConn(conn, c.options.Keepalive)
	go wsConn.runPingLoop()
	logrus.Debugf("%s://%s established successfully, toh latency %s",
		network, addr, time.Since(t1))
	return
}

type nhooyrWSConn struct {
	*websocket.Conn
	pingInterval    time.Duration
	lastActiveTime  time.Time
	connIdleTimeout time.Duration
}

func newNhooyrWSConn(conn *websocket.Conn, pingInterval time.Duration) *nhooyrWSConn {
	return &nhooyrWSConn{
		Conn:            conn,
		pingInterval:    pingInterval,
		lastActiveTime:  time.Now(),
		connIdleTimeout: 75 * time.Second,
	}
}

func (c *nhooyrWSConn) runPingLoop() {
	if c.pingInterval == 0 {
		return
	}
	for {
		time.Sleep(c.pingInterval)
		if time.Since(c.lastActiveTime) > c.connIdleTimeout {
			logrus.Debug("ping: exited. connection reached the max idle time ", c.connIdleTimeout)
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(),
			spec.MinDuration(2*time.Second, c.pingInterval))
		defer cancel()
		err := c.Conn.Ping(ctx)
		if err != nil {
			logrus.Debug("ping: ", err)
			break
		}
	}
}

func (c *nhooyrWSConn) Read(ctx context.Context) (b []byte, err error) {
	_, b, err = c.Conn.Read(ctx)
	c.lastActiveTime = time.Now()
	return
}
func (c *nhooyrWSConn) Write(ctx context.Context, p []byte) error {
	c.lastActiveTime = time.Now()
	return c.Conn.Write(ctx, websocket.MessageBinary, p)
}

func (c *nhooyrWSConn) LocalAddr() net.Addr {
	return nil
}

func (c *nhooyrWSConn) Close(code int, reason string) error {
	return c.Conn.Close(websocket.StatusCode(code), reason)
}
