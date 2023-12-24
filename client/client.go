package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"
	D "github.com/rkonfj/toh/dns"
	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/rkonfj/toh/transport/ws"
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

func (c *TohClient) DialContext(ctx context.Context, network, addr string) (
	conn net.Conn, err error) {
	u, err := url.Parse(c.options.Server)
	if err != nil {
		return nil, errors.New("invalid server url")
	}
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else if u.Scheme == "https" {
		u.Scheme = "wss"
	}
	wsConn, err := ws.Connect(spec.ConnectParameters{
		URL:       u,
		Key:       c.options.Key,
		Network:   network,
		Addr:      addr,
		Header:    c.options.Headers,
		Keepalive: c.options.Keepalive,
	}, c.directNetDial)
	if err != nil {
		return nil, err
	}

	connEntry := ConnEntry{
		// Use the nonce returned by the server (some older versions of servers do not support nonce)
		Nonce:      wsConn.Nonce(),
		LocalAddr:  wsConn.LocalAddr().String(),
		lastRWTime: time.Now(),
		ct:         c.conntrack,
	}

	connEntry.RemoteHost = addr
	connEntry.Proto = network
	connEntry.RemoteAddr = wsConn.RemoteAddr().String()
	connEntry.add()

	wsConn.(spec.StreamConnListener).SetOnClose(func() {
		connEntry.remove()
	})

	wsConn.(spec.StreamConnListener).SetOnReadWrite(func() {
		connEntry.lastRWTime = time.Now()
	})

	go wsConn.(spec.StreamConnKeeper).Keepalive()

	switch network {
	case "tcp", "tcp4", "tcp6":
		conn = spec.NewConn(wsConn)
	case "udp", "udp4", "udp6":
		conn = spec.NewPacketConn(wsConn)
	default:
		err = spec.ErrUnsupportNetwork
	}
	return
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
