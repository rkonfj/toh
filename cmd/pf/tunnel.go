package pf

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rkonfj/toh/client"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Forwards    []string
	Server, Key string
	UDPBuf      int64
	TCPBuf      int64
	Keepalive   time.Duration
	Headers     []string
}

type TunnelManager struct {
	opts     Options
	client   *client.TohClient
	forwards []mapping
	wg       sync.WaitGroup
}

type mapping struct {
	network string
	local   string
	remote  string
	bo      backoff.BackOff
}

func NewTunnelManager(opts Options) (*TunnelManager, error) {
	clientOpts := client.Options{
		Server:    opts.Server,
		Key:       opts.Key,
		Keepalive: opts.Keepalive,
		Headers:   http.Header{},
	}

	for _, kv := range opts.Headers {
		kvs := strings.Split(kv, ":")
		if len(kvs) != 2 {
			logrus.Warnf("incorrect header format: %s, correct should be key:value", kv)
			continue
		}
		clientOpts.Headers.Add(strings.TrimSpace(kvs[0]), strings.TrimSpace(kvs[1]))
	}

	c, err := client.NewTohClient(clientOpts)
	if err != nil {
		return nil, err
	}

	var forwards []mapping

	for _, f := range opts.Forwards {
		rawMp := strings.Split(f, "/")
		if len(rawMp) < 2 || len(rawMp) > 3 {
			return nil, errors.New("invalid forward " + f)
		}
		mp := mapping{network: rawMp[0], bo: backoff.NewExponentialBackOff()}
		if len(rawMp) == 2 {
			mp.local = "stdio"
			mp.remote = rawMp[1]
			logrus.SetOutput(os.Stderr)
		} else {
			if len(rawMp) == 0 {
				mp.local = "stdio"
			} else {
				mp.local = rawMp[1]
			}
			mp.remote = rawMp[2]
		}
		forwards = append(forwards, mp)
	}

	return &TunnelManager{
		client:   c,
		wg:       sync.WaitGroup{},
		forwards: forwards,
		opts:     opts,
	}, nil
}

func (t *TunnelManager) Run() {
	t.wg.Add(len(t.forwards))

	for _, f := range t.forwards {
		logrus.Infof("listen on %s for %s://%s now", f.local, f.network, f.remote)
		go t.forward(f)
	}
	t.wg.Wait()
}

func (t *TunnelManager) forward(mp mapping) {
	defer t.wg.Done()
	var err error
	switch mp.network {
	case "tcp":
		err = t.forwardTCP(mp)
	case "udp":
		err = t.forwardUDP(mp)
	default:
		logrus.Error("unsupport network ", mp.network)
	}
	if err != nil {
		logrus.Error(err)
	}
	time.Sleep(mp.bo.NextBackOff())
	t.wg.Add(1)
	go t.forward(mp)
}

func (t *TunnelManager) forwardTCP(mp mapping) (err error) {
	if mp.local == "stdio" {
		rConn, _err := t.client.DialTCP(context.Background(), mp.remote)
		if _err != nil {
			err = _err
			return
		}
		t.pipe(&stdRW{Reader: os.Stdin, Writer: os.Stdout}, rConn)
		return
	}

	listener, err := net.Listen(mp.network, mp.local)
	if err != nil {
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}

		rConn, err := t.client.DialTCP(context.Background(), mp.remote)
		if err != nil {
			conn.Close()
			break
		}
		mp.bo.Reset()
		go t.pipe(conn, rConn)
	}
	listener.Close()
	return
}

func (t *TunnelManager) forwardUDP(mp mapping) (err error) {
	if mp.local == "stdio" {
		rConn, _err := t.client.DialUDP(context.Background(), mp.remote)
		if _err != nil {
			err = _err
			return
		}
		t.pipe(&stdRW{Reader: os.Stdin, Writer: os.Stdout}, rConn)
		return
	}
	host, port, err := net.SplitHostPort(mp.local)
	if err != nil {
		return
	}

	_port, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: int(_port),
		IP:   net.ParseIP(host),
	})
	if err != nil {
		return
	}
	rConn, err := t.client.DialUDP(context.Background(), mp.remote)
	if err == nil {
		mp.bo.Reset()
		t.pipeUDP(conn, rConn)
	}
	conn.Close()
	return
}

func (t *TunnelManager) pipe(l, r io.ReadWriteCloser) {
	defer l.Close()
	defer r.Close()
	go io.CopyBuffer(l, r, make([]byte, t.opts.TCPBuf))
	io.CopyBuffer(r, l, make([]byte, t.opts.TCPBuf))
}

func (t *TunnelManager) pipeUDP(l net.PacketConn, r net.Conn) {
	defer l.Close()
	defer r.Close()
	var localAddr net.Addr
	go func() {
		buf := make([]byte, t.opts.UDPBuf)
		for {
			n, _localAddr, err := l.ReadFrom(buf)
			localAddr = _localAddr
			if err != nil {
				break
			}
			_, err = r.Write(buf[:n])
			if err != nil {
				break
			}
		}
	}()

	buf := make([]byte, t.opts.UDPBuf)
	for {
		n, err := r.Read(buf)
		if err != nil {
			break
		}
		_, err = l.WriteTo(buf[:n], localAddr)
		if err != nil {
			break
		}
	}
}

type stdRW struct {
	io.Reader
	io.Writer
}

func (s *stdRW) Read(p []byte) (n int, err error) {
	return s.Reader.Read(p)
}

func (s *stdRW) Write(p []byte) (n int, err error) {
	return s.Writer.Write(p)
}

func (s *stdRW) Close() error {
	return nil
}
