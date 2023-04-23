package pf

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/rkonfj/toh/client"
	"github.com/sirupsen/logrus"
)

type Options struct {
	forwards       []string
	server, apiKey string
}

type TunnelManager struct {
	client   *client.TohClient
	forwards []mapping
	wg       sync.WaitGroup
}

type mapping struct {
	network string
	local   string
	remote  string
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
		forwards = append(forwards, mapping{network: mp[0], local: mp[1], remote: mp[2]})
	}

	return &TunnelManager{
		client:   c,
		wg:       sync.WaitGroup{},
		forwards: forwards,
	}, nil
}

func (t *TunnelManager) Run() {
	t.wg.Add(len(t.forwards))

	for _, f := range t.forwards {
		logrus.Infof("listen %s://%s for %s now", f.network, f.local, f.remote)
		go t.forward(f)
	}
	t.wg.Wait()
}

func (t *TunnelManager) forward(mp mapping) {
	if mp.network == "tcp" {
		listener, err := net.Listen(mp.network, mp.local)
		if err != nil {
			logrus.Error(err)
			t.wg.Done()
			return
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.Error(err)
				break
			}

			rConn, err := t.client.DialTCP(context.Background(), mp.remote)
			if err != nil {
				conn.Close()
				logrus.Error(err)
			}

			go pipe(conn, rConn)
		}
		t.wg.Done()
		return
	}

	if mp.network == "udp" {
		host, port, err := net.SplitHostPort(mp.local)
		if err != nil {
			logrus.Error(err)
			t.wg.Done()
			return
		}

		_port, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			logrus.Error(err)
			t.wg.Done()
			return
		}

		conn, err := net.ListenUDP("udp", &net.UDPAddr{
			Port: int(_port),
			IP:   net.ParseIP(host),
		})
		if err != nil {
			logrus.Error(err)
			t.wg.Done()
			return
		}
		rConn, err := t.client.DialUDP(context.Background(), mp.remote)
		if err != nil {
			logrus.Error(err)
			t.wg.Done()
		}
		pipeUDP(conn, rConn)
		t.forward(mp)
	}
	logrus.Error("unsupport network ", mp.network)
	t.wg.Done()
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
			n, err = r.Write(buf[:n])
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
		n, err = l.WriteTo(buf[:n], localAddr)
		if err != nil {
			r.Close()
			break
		}
	}
}
