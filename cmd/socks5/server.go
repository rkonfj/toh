package socks5_cmd

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/rkonfj/toh/client"
	"github.com/rkonfj/toh/cmd/socks5/ruleset"
	"github.com/rkonfj/toh/socks5"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Geoip2  string      `yaml:"geoip2"`
	Listen  string      `yaml:"listen"`
	Servers []TohServer `yaml:"servers"`
}

type TohServer struct {
	Name    string `yaml:"name"`
	Api     string `yaml:"api"`
	Key     string `yaml:"key"`
	Ruleset string `yaml:"ruleset"`
}

type RulebasedSocks5Server struct {
	opts          Options
	servers       []*ToH
	defaultDialer net.Dialer
	geoip2db      *geoip2.Reader
}

type ToH struct {
	name    string
	client  *client.TohClient
	ruleset *ruleset.Ruleset
}

func NewSocks5Server(dataPath string, opts *Options) (*RulebasedSocks5Server, error) {
	var servers []*ToH
	for _, s := range opts.Servers {
		c, err := client.NewTohClient(client.Options{
			ServerAddr: s.Api,
			ApiKey:     s.Key,
		})
		if err != nil {
			return nil, err
		}

		var rs *ruleset.Ruleset
		if r, ok := strings.CutPrefix(s.Ruleset, "b64,"); ok {
			if strings.HasPrefix(r, "https") {
				rs, err = ruleset.NewRulesetFromURL(s.Name, r, c.DialTCP, true)
			} else {
				rs, err = ruleset.NewRulesetFromFileB64(s.Name, ensureAbsPath(dataPath, r))
			}
		} else {
			if strings.HasPrefix(s.Ruleset, "https") {
				rs, err = ruleset.NewRulesetFromURL(s.Name, s.Ruleset, c.DialTCP, false)
			} else {
				rs, err = ruleset.NewRulesetFromFile(s.Name, ensureAbsPath(dataPath, s.Ruleset))
			}
		}
		if err != nil {
			return nil, err
		}
		server := &ToH{
			name:    s.Name,
			client:  c,
			ruleset: rs,
		}
		servers = append(servers, server)
	}
	httpClient := securityHttpClient(servers)
	db, err := openGeoip2(httpClient, dataPath, opts.Geoip2)
	if err != nil {
		return nil, err
	}
	return &RulebasedSocks5Server{
		opts:          *opts,
		servers:       servers,
		defaultDialer: net.Dialer{},
		geoip2db:      db,
	}, nil
}

func (s *RulebasedSocks5Server) Run() error {
	ss := socks5.NewSocks5Server(socks5.Options{
		Listen:    s.opts.Listen,
		TCPDialer: s.dialTCP,
		UDPDialer: s.dialUDP,
	})
	return ss.Run()
}

func (s *RulebasedSocks5Server) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		c, err := s.geoip2db.Country(ip)
		if err != nil {
			return nil, err
		}

		for _, toh := range s.servers {
			if toh.ruleset.CountryMatch(c.Country.IsoCode) {
				logrus.Infof("%s using %s", addr, toh.name)
				return toh.client.DialTCP(ctx, addr)
			}
		}
		goto direct
	}

	for _, toh := range s.servers {
		if toh.ruleset.SpecialMatch(host) {
			logrus.Infof("%s using %s", addr, toh.name)
			return toh.client.DialTCP(ctx, addr)
		}
	}

	for _, toh := range s.servers {
		if toh.ruleset.WildcardMatch(host) {
			logrus.Infof("%s using %s", addr, toh.name)
			return toh.client.DialTCP(ctx, addr)
		}
	}

direct:
	logrus.Infof("%s using direct", addr)
	return s.defaultDialer.DialContext(ctx, "tcp", addr)
}

func (s *RulebasedSocks5Server) dialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return s.servers[rand.Intn(len(s.servers))].client.DialUDP(ctx, addr)
}

func selectServer(servers []*ToH) *ToH {
	return servers[rand.Intn(len(servers))]
}

func securityHttpClient(servers []*ToH) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return selectServer(servers).client.DialTCP(ctx, addr)
			},
		},
	}
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
	logrus.Info("downloading country.mmdb to ", dataPath)
	mmdbPath := filepath.Join(dataPath, "country.mmdb")
	resp, err := hc.Get("https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb")
	if err != nil {
		logrus.Error("download geoip2 country.mmdb ", err)
		return mmdbPath
	}
	defer resp.Body.Close()
	mmdb, err := os.OpenFile(mmdbPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("open %s %s", mmdbPath, err)
		return mmdbPath
	}
	defer mmdb.Close()
	io.Copy(mmdb, resp.Body)
	return mmdbPath
}

func ensureAbsPath(datapath, filename string) string {
	if filename == "" {
		return ""
	}
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(datapath, filename)
}
