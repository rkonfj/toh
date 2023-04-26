package client

import (
	"context"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohClient struct {
	options    Options
	httpClient *http.Client
}

type Options struct {
	ServerAddr string
	ApiKey     string
}

func NewTohClient(options Options) (*TohClient, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
				dialer := net.Dialer{}
				ipAddr, err := spec.ResolveIP(ctx, func(ctx context.Context, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, "udp", addr)
				}, addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, ipAddr)
			},
		},
	}
	return &TohClient{
		options:    options,
		httpClient: httpClient,
	}, nil
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

func (c *TohClient) dial(ctx context.Context, network, addr string) (conn *websocket.Conn, remoteIP net.IP, remotePort int, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	dnsLookupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(dnsLookupCtx, "ip", host)
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
