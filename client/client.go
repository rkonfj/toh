package client

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
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
	ServerAddr string
	ApiKey     string
}

func NewTohClient(options Options) (*TohClient, error) {
	if _, err := url.ParseRequestURI(options.ServerAddr); err != nil {
		return nil, err
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

				ips, err := c.directLookupIP4(host)
				if err != nil {
					return
				}
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("%s:%s", ips[rand.Intn(len(ips))], port))
			},
		},
	}
	return c, nil
}

func (c *TohClient) DNSExchange(dnServer string, query *dns.Msg) (resp *dns.Msg, err error) {
	return c.dnsExchange(dnServer, query, false)
}

func (c *TohClient) LookupIP4(host string) (ips []net.IP, err error) {
	return c.lookupIP(host, dns.TypeA, false)
}

func (c *TohClient) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	conn, ip, port, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return spec.NewWSStreamConn(&NhooyrWSConn{conn}, &net.TCPAddr{IP: ip, Port: port}), nil
}

func (c *TohClient) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	conn, ip, port, err := c.dial(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return spec.NewWSStreamConn(&NhooyrWSConn{conn}, &net.UDPAddr{IP: ip, Port: port}), nil
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
	for _, dnServer := range []string{"8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53"} {
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
	}
	if len(ips) == 0 {
		err = fmt.Errorf("resolve %s : no type %s was found", host, dns.Type(t))
	}
	return
}

func (c *TohClient) directLookupIP4(host string) (ips []net.IP, err error) {
	return c.lookupIP(host, dns.TypeA, true)
}

func (c *TohClient) dial(ctx context.Context, network, addr string) (conn *websocket.Conn, remoteIP net.IP, remotePort int, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	ips, err := c.directLookupIP4(host)
	if err != nil {
		return
	}

	_port, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return
	}

	remoteIP = ips[rand.Intn(len(ips))]
	remotePort = int(_port)

	handshake := http.Header{}
	handshake.Add("x-toh-key", c.options.ApiKey)
	handshake.Add("x-toh-net", network)
	handshake.Add("x-toh-addr", addr)

	t1 := time.Now()
	conn, _, err = websocket.Dial(ctx, c.options.ServerAddr, &websocket.DialOptions{
		HTTPHeader: handshake, HTTPClient: c.httpClient,
	})
	if err != nil {
		if strings.Contains(err.Error(), "401") {
			err = spec.ErrAuth
			return
		}
		return
	}
	logrus.Debugf("%s://%s established successfully, toh latency %s", network, addr, time.Since(t1))
	return
}

type NhooyrWSConn struct {
	*websocket.Conn
}

func (c *NhooyrWSConn) Read(ctx context.Context) (b []byte, err error) {
	_, b, err = c.Conn.Read(ctx)
	return
}
func (c *NhooyrWSConn) Write(ctx context.Context, p []byte) error {
	return c.Conn.Write(ctx, websocket.MessageBinary, p)
}

func (c *NhooyrWSConn) LocalAddr() net.Addr {
	return nil
}

func (c *NhooyrWSConn) Close(code int, reason string) error {
	return c.Conn.Close(websocket.StatusCode(code), reason)
}
