package pf

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rkonfj/toh/client"
	"github.com/rkonfj/toh/socks5"
	"github.com/sirupsen/logrus"
)

type Options struct {
	forwards       []string
	server, apiKey string
	socks5         string
}

type TunnelManager struct {
	client   *client.TohClient
	forwards []mapping
	socks5   string
	wg       sync.WaitGroup
}

type mapping struct {
	network string
	local   string
	remote  string
	bo      backoff.BackOff
}

func NewTunnelManager(opts Options) (*TunnelManager, error) {
	c, err := client.NewTohClient(client.Options{
		ServerAddr: opts.server,
		ApiKey:     opts.apiKey,
	})

	if err != nil {
		return nil, err
	}

	var forwards []mapping

	for _, f := range opts.forwards {
		mp := strings.Split(f, "/")
		if len(mp) != 3 {
			return nil, errors.New("invalid forward " + f)
		}
		forwards = append(forwards, mapping{network: mp[0], local: mp[1], remote: mp[2], bo: backoff.NewExponentialBackOff()})
	}

	return &TunnelManager{
		client:   c,
		wg:       sync.WaitGroup{},
		forwards: forwards,
		socks5:   opts.socks5,
	}, nil
}

func (t *TunnelManager) Run() {
	t.wg.Add(len(t.forwards))

	if t.socks5 != "" {
		t.wg.Add(1)
		ss := socks5.NewSocks5Server(socks5.Options{
			Listen:    t.socks5,
			TCPDialer: t.client.DialTCP,
			UDPDialer: t.client.DialUDP,
		})
		go func() {
			defer t.wg.Done()
			err := ss.Run()
			if err != nil {
				logrus.Error(err)
			}
		}()
	}

	for _, f := range t.forwards {
		logrus.Infof("listen on %s for %s://%s now", f.local, f.network, f.remote)
		go t.forward(f)
	}
	t.wg.Wait()
}

func (t *TunnelManager) forward(mp mapping) {
	defer t.wg.Done()
	if mp.network == "tcp" {
		listener, err := net.Listen(mp.network, mp.local)
		if err != nil {
			logrus.Error("[tcp] ", err)
			return
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.Error("[tcp] ", err)
				break
			}

			rConn, err := t.client.DialTCP(context.Background(), mp.remote)
			if err != nil {
				conn.Close()
				logrus.Error("[tcp] ", err)
				break
			}
			mp.bo.Reset()
			go pipe(conn, rConn)
		}
		listener.Close()
		time.Sleep(mp.bo.NextBackOff())
		t.wg.Add(1)
		go t.forward(mp)
		return
	}

	if mp.network == "udp" {
		host, port, err := net.SplitHostPort(mp.local)
		if err != nil {
			logrus.Error("[udp] ", err)
			return
		}

		_port, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			logrus.Error("[udp] ", err)
			return
		}

		conn, err := net.ListenUDP("udp", &net.UDPAddr{
			Port: int(_port),
			IP:   net.ParseIP(host),
		})
		if err != nil {
			logrus.Error("[udp] ", err)
			return
		}
		rConn, err := t.client.DialUDP(context.Background(), mp.remote)
		if err == nil {
			mp.bo.Reset()
			pipeUDP(conn, rConn)
		}
		if err != nil {
			logrus.Error("[udp] ", err)
		}
		conn.Close()
		time.Sleep(mp.bo.NextBackOff())
		t.wg.Add(1)
		go t.forward(mp)
		return
	}
	logrus.Error("unsupport network ", mp.network)
}

func pipe(l, r net.Conn) {
	go func() {
		io.Copy(l, r)
		l.Close()
	}()
	io.Copy(r, l)
	r.Close()
}

func pipeUDP(l net.PacketConn, r net.Conn) {
	var localAddr net.Addr
	go func() {
		for {
			buf := make([]byte, 1024)
			n, _localAddr, err := l.ReadFrom(buf)
			localAddr = _localAddr
			if err != nil {
				r.Close()
				break
			}
			_, err = r.Write(buf[:n])
			if err != nil {
				l.Close()
				break
			}
		}
	}()

	for {
		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		if err != nil {
			l.Close()
			break
		}
		_, err = l.WriteTo(buf[:n], localAddr)
		if err != nil {
			r.Close()
			break
		}
	}
}
