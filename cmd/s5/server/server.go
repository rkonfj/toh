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
	Cfg         Config
	DataRoot    string
	DNSListen   string
	DNSUpstream string
	DNSEvict    time.Duration
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
	cfg := opts.Cfg
	socks5Server = &RulebasedSocks5Server{
		opts:           opts,
		servers:        []*Server{},
		groups:         []*Group{},
		defaultDialer:  net.Dialer{},
		dnsClient:      &dns.Client{},
		dnsCache:       make(map[string]*cacheEntry),
		dnsCacheTicker: time.NewTicker(time.Duration(math.Max(float64(opts.DNSEvict/20), float64(time.Minute)))),
	}
	for _, s := range cfg.Servers {
		var c *client.TohClient
		c, err = client.NewTohClient(client.Options{
			ServerAddr: s.Api,
			ApiKey:     s.Key,
		})
		if err != nil {
			return
		}

		server := &Server{
			name:   s.Name,
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
		if s.Ruleset != nil {
			server.ruleset, err = ruleset.Parse(c, s.Name, s.Ruleset, opts.DataRoot)
			if err != nil {
				return
			}
		}
		go healthcheck(server, s.Healthcheck)
		socks5Server.servers = append(socks5Server.servers, server)
	}

	for _, g := range cfg.Groups {
		group := &Group{
			name:    g.Name,
			servers: []*Server{},
		}
		for _, s := range socks5Server.servers {
			if slices.Contains(g.Servers, s.name) {
				group.servers = append(group.servers, s)
			}
		}
		if len(group.servers) == 0 {
			continue
		}
		if g.Ruleset != nil {
			group.ruleset, err = ruleset.Parse(selectServer(group.servers).client, g.Name, g.Ruleset, opts.DataRoot)
			if err != nil {
				return
			}
		}
		socks5Server.groups = append(socks5Server.groups, group)
	}

	socks5Server.geoip2db, err = openGeoip2(selectServer(socks5Server.servers).httpClient, opts.DataRoot, cfg.Geoip2)
	if err != nil {
		return
	}
	logrus.Infof("loaded total %d proxy servers and %d groups", len(socks5Server.servers), len(socks5Server.groups))
	ruleset.ResetCache()
	return
}

func (s *RulebasedSocks5Server) Run() error {
	ss := socks5.NewSocks5Server(socks5.Options{
		Listen:               s.opts.Cfg.Listen,
		TCPDialContext:       s.dialTCP,
		UDPDialContext:       s.dialUDP,
		TrafficEventConsumer: logTrafficEvent,
	})
	go s.runDNSIfNeeded()
	return ss.Run()
}

func (s *RulebasedSocks5Server) dialTCP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
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
		log.Infof("%s using %s latency %s", addr, proxyId, server.latency)
		conn, err = server.client.DialTCP(ctx, addr)
		return
	}

	log.Infof("%s using direct", addr)
	dialerName = "direct"
	conn, err = s.defaultDialer.DialContext(ctx, "tcp", addr)
	return
}

func (s *RulebasedSocks5Server) dialUDP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
	toh := selectServer(s.servers)
	dialerName = toh.name
	conn, err = toh.client.DialUDP(ctx, addr)
	return
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
