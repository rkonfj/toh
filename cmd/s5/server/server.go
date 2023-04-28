package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	cfg           Config
	servers       []*Server
	groups        []*Group
	defaultDialer net.Dialer
	geoip2db      *geoip2.Reader
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

func NewSocks5Server(dataPath string, cfg Config) (socks5Server *RulebasedSocks5Server, err error) {
	socks5Server = &RulebasedSocks5Server{
		cfg:           cfg,
		servers:       []*Server{},
		groups:        []*Group{},
		defaultDialer: net.Dialer{},
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
						addr, err := spec.ResolveIP(ctx, c.DialTCP, addr)
						if err != nil {
							return nil, err
						}
						return c.DialTCP(ctx, addr)
					},
				},
			},
		}
		if s.Ruleset != nil {
			server.ruleset, err = ruleset.Parse(c, s.Name, s.Ruleset, dataPath)
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
			group.ruleset, err = ruleset.Parse(selectServer(group.servers).client, g.Name, g.Ruleset, dataPath)
			if err != nil {
				return
			}
		}
		socks5Server.groups = append(socks5Server.groups, group)
	}

	socks5Server.geoip2db, err = openGeoip2(selectServer(socks5Server.servers).httpClient, dataPath, cfg.Geoip2)
	if err != nil {
		return
	}
	logrus.Infof("total %d proxy servers and %d groups loaded", len(socks5Server.servers), len(socks5Server.groups))
	ruleset.ResetCache()
	return
}

func (s *RulebasedSocks5Server) Run() error {
	ss := socks5.NewSocks5Server(socks5.Options{
		Listen:               s.cfg.Listen,
		TCPDialContext:       s.dialTCP,
		UDPDialContext:       s.dialUDP,
		TrafficEventConsumer: logTrafficEvent,
	})
	return ss.Run()
}

func (s *RulebasedSocks5Server) dialUDP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
	toh := selectServer(s.servers)
	dialerName = toh.name
	conn, err = toh.client.DialUDP(ctx, addr)
	return
}

func selectServer(servers []*Server) *Server {
	sort.Slice(servers, func(i, j int) bool {
		return servers[i].latency < servers[j].latency
	})
	return servers[0]
}

func openGeoip2(httpClient *http.Client, dataPath, geoip2Path string) (*geoip2.Reader, error) {
	db, err := geoip2.Open(getGeoip2Path(httpClient, dataPath, geoip2Path))
	if err != nil {
		if strings.Contains(err.Error(), "invalid MaxMind") {
			logrus.Info("removed invalid country.mmdb file")
			os.Remove(geoip2Path)
			return openGeoip2(httpClient, dataPath,
				getGeoip2Path(httpClient, dataPath, ""))
		}
		if errors.Is(err, os.ErrNotExist) {
			return openGeoip2(httpClient, dataPath,
				getGeoip2Path(httpClient, dataPath, ""))
		}
		return nil, err
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
	logrus.Infof("downloading country.mmdb to %s. this can take up to 2m0s", dataPath)
	mmdbPath := filepath.Join(dataPath, "country.mmdb")
	resp, err := hc.Get("https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb")
	if err != nil {
		logrus.Error(err)
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
