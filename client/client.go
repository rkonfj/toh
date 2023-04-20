package client

import (
	"context"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohClient struct {
	options Options
}

type Options struct {
	ServerAddr string
	ApiKey     string
}

func NewTohClient(options Options) (*TohClient, error) {
	return &TohClient{
		options: options,
	}, nil
}

func (c *TohClient) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	conn, ip, port, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return spec.NewWSTCPConn(conn, &net.TCPAddr{IP: ip, Port: port}), nil
}

func (c *TohClient) dial(ctx context.Context, network, addr string) (conn *websocket.Conn, remoteIP net.IP, remotePort int, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	dnsLookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
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
	conn, _, err = websocket.Dial(ctx, c.options.ServerAddr, &websocket.DialOptions{HTTPHeader: handshake})
	if err != nil {
		return
	}
	logrus.Infof("%s://%s established successfully, toh latency %s", network, addr, time.Since(t1))
	return
}
