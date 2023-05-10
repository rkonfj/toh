package server

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"github.com/rkonfj/toh/client"
	"github.com/rkonfj/toh/cmd/s5/ruleset"
	"github.com/rkonfj/toh/socks5"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type Config struct {
	Geoip2  string        `yaml:"geoip2"`
	Listen  string        `yaml:"listen"`
	Servers []TohServer   `yaml:"servers"`
	Groups  []ServerGroup `yaml:"groups"`
}

type Options struct {
	Cfg           Config
	AdvertiseAddr string
	DataRoot      string
	DNSFake       string
	DNSListen     string
	DNSUpstream   string
	DNSEvict      time.Duration
}

type TohServer struct {
	Name        string   `yaml:"name"`
	Api         string   `yaml:"api"`
	Key         string   `yaml:"key"`
	Ruleset     []string `yaml:"ruleset"`
	Healthcheck string   `yaml:"healthcheck"`
}

type ServerGroup struct {
	Name    string   `yaml:"name"`
	Servers []string `yaml:"servers"`
	Ruleset []string `yaml:"ruleset"`
}

type RulebasedSocks5Server struct {
	opts           Options
	servers        []*Server
	groups         []*Group
	defaultDialer  net.Dialer
	geoip2db       *geoip2.Reader
	dnsClient      *dns.Client
	dnsCache       map[string]*cacheEntry
	dnsCacheLock   sync.RWMutex
	dnsCacheTicker *time.Ticker
}

type Server struct {
	name       string
	client     *client.TohClient
	httpClient *http.Client
	ruleset    *ruleset.Ruleset
	latency    time.Duration
}

type Group struct {
	name    string
	servers []*Server
	ruleset *ruleset.Ruleset
}

func NewSocks5Server(opts Options) (socks5Server *RulebasedSocks5Server, err error) {
	socks5Server = &RulebasedSocks5Server{
		opts:           opts,
		servers:        []*Server{},
		groups:         []*Group{},
		defaultDialer:  net.Dialer{},
		dnsClient:      &dns.Client{},
		dnsCache:       make(map[string]*cacheEntry),
		dnsCacheTicker: time.NewTicker(time.Duration(math.Max(float64(opts.DNSEvict/20), float64(time.Minute)))),
	}

	err = socks5Server.loadServers()
	if err != nil {
		return
	}

	err = socks5Server.loadGroups()
	if err != nil {
		return
	}
	ruleset.ResetCache()

	logrus.Infof("total loaded %d proxy servers and %d groups", len(socks5Server.servers), len(socks5Server.groups))

	socks5Server.geoip2db, err = openGeoip2(selectServer(socks5Server.servers).httpClient, opts.DataRoot, opts.Cfg.Geoip2)
	if err != nil {
		return
	}
	return
}

func (s *RulebasedSocks5Server) Run() error {
	opts := socks5.Options{
		Listen:               s.opts.Cfg.Listen,
		TCPDialContext:       s.dialTCP,
		UDPDialContext:       s.dialUDP,
		TrafficEventConsumer: logTrafficEvent,
	}
	if s.opts.AdvertiseAddr != "" {
		ipPort := strings.Split(s.opts.AdvertiseAddr, ":")
		if len(ipPort) != 2 {
			return errors.New("advertise address format error")
		}
		port, err := strconv.Atoi(ipPort[1])
		if err != nil {
			return err
		}
		opts.AdvertiseIP = ipPort[0]
		opts.AdvertisePort = uint16(port)
	}
	ss, err := socks5.NewSocks5Server(opts)
	if err != nil {
		return err
	}
	go s.runDNSIfNeeded()
	return ss.Run()
}

func (s *RulebasedSocks5Server) loadServers() (err error) {
	for _, srv := range s.opts.Cfg.Servers {
		var c *client.TohClient
		c, err = client.NewTohClient(client.Options{
			ServerAddr: srv.Api,
			ApiKey:     srv.Key,
		})
		if err != nil {
			return
		}

		server := &Server{
			name:   srv.Name,
			client: c,
			httpClient: &http.Client{
				Timeout: 120 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return c.DialTCP(ctx, addr)
					},
				},
			},
		}
		if srv.Ruleset != nil {
			server.ruleset, err = ruleset.Parse(c, srv.Name, srv.Ruleset, s.opts.DataRoot)
			if err != nil {
				return
			}
		}
		go healthcheck(server, srv.Healthcheck)
		s.servers = append(s.servers, server)
	}
	return
}

func (s *RulebasedSocks5Server) loadGroups() (err error) {
	for _, g := range s.opts.Cfg.Groups {
		group := &Group{
			name:    g.Name,
			servers: []*Server{},
		}
		for _, s := range s.servers {
			if slices.Contains(g.Servers, s.name) {
				group.servers = append(group.servers, s)
			}
		}
		if len(group.servers) == 0 {
			continue
		}
		if g.Ruleset != nil {
			group.ruleset, err = ruleset.Parse(selectServer(group.servers).client, g.Name, g.Ruleset, s.opts.DataRoot)
			if err != nil {
				return
			}
		}
		s.groups = append(s.groups, group)
	}
	return
}

func (s *RulebasedSocks5Server) dial(ctx context.Context, addr, network string) (dialerName string, conn net.Conn, err error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	server, group, err := s.selectProxyServer(host)
	if err != nil {
		return
	}

	log := logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr))
	if server != nil {
		dialerName = server.name
		proxyId := server.name
		if group != "" {
			proxyId = group + "." + server.name
		}
		log.Infof("%s://%s using %s latency %s", network, addr, proxyId, server.latency)
		if network == "tcp" {
			conn, err = server.client.DialTCP(ctx, addr)
		} else if network == "udp" {
			conn, err = server.client.DialUDP(ctx, addr)
		} else {
			err = errors.New("unsupported network " + network)
		}
		return
	}

	log.Infof("%s://%s using direct", network, addr)
	dialerName = "direct"
	conn, err = s.defaultDialer.DialContext(ctx, network, addr)
	return
}

func (s *RulebasedSocks5Server) dialTCP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
	return s.dial(ctx, addr, "tcp")
}

func (s *RulebasedSocks5Server) dialUDP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
	if len(s.opts.DNSUpstream) > 0 && strings.Contains(addr, s.opts.DNSFake) {
		dialerName = "direct"
		conn, err = s.defaultDialer.Dial("udp", s.opts.DNSListen)
		return
	}
	return s.dial(ctx, addr, "udp")
}

func selectServer(servers []*Server) *Server {
	s := make([]*Server, len(servers))
	copy(s, servers)
	sort.Slice(s, func(i, j int) bool {
		return s[i].latency < s[j].latency
	})
	return s[0]
}

func openGeoip2(httpClient *http.Client, dataPath, geoip2Path string) (*geoip2.Reader, error) {
	db, err := geoip2.Open(getGeoip2Path(httpClient, dataPath, geoip2Path))
	if err != nil {
		if strings.Contains(err.Error(), "invalid MaxMind") {
			os.Remove(geoip2Path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return openGeoip2(httpClient, dataPath, getGeoip2Path(httpClient, dataPath, ""))
	}
	return db, nil
}

func getGeoip2Path(hc *http.Client, dataPath, geoip2Path string) string {
	if geoip2Path != "" {
		if filepath.IsAbs(geoip2Path) {
			return geoip2Path
		}
		return filepath.Join(dataPath, geoip2Path)
	}
	logrus.Infof("downloading country.mmdb to %s (this can take up to 2m0s)", dataPath)
	mmdbPath := filepath.Join(dataPath, "country.mmdb")
	resp, err := hc.Get("https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb")
	if err != nil {
		logrus.Error("download country.mmdb error: ", err.Error())
		return mmdbPath
	}
	defer resp.Body.Close()
	mmdb, err := os.OpenFile(mmdbPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("open db %s error: %s", mmdbPath, err)
		return mmdbPath
	}
	defer mmdb.Close()
	_, err = io.Copy(mmdb, resp.Body)
	if err != nil {
		logrus.Error(err)
	}

	return mmdbPath
}
