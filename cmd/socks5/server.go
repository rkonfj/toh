package socks5_cmd

import (
	"context"
	"math/rand"
	"net"
	"strings"

	"github.com/rkonfj/toh/client"
	"github.com/rkonfj/toh/cmd/socks5/ruleset"
	"github.com/rkonfj/toh/socks5"
	"github.com/sirupsen/logrus"
)

type Options struct {
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
}

type ToH struct {
	name    string
	client  *client.TohClient
	ruleset *ruleset.Ruleset
}

func NewSocks5Server(opts *Options) (*RulebasedSocks5Server, error) {
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
		if strings.HasPrefix(s.Ruleset, "https") {
			rs, err = ruleset.NewRulesetFromURL(s.Name, s.Ruleset)
		} else {
			rs, err = ruleset.NewRulesetFromFile(s.Name, s.Ruleset)
		}
		if err != nil {
			return nil, err
		}
		servers = append(servers, &ToH{
			name:    s.Name,
			client:  c,
			ruleset: rs,
		})
	}
	return &RulebasedSocks5Server{
		opts:          *opts,
		servers:       servers,
		defaultDialer: net.Dialer{},
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
	logrus.Infof("%s using direct", addr)
	return s.defaultDialer.DialContext(ctx, "tcp", addr)
}

func (s *RulebasedSocks5Server) dialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return s.servers[rand.Intn(len(s.servers))].client.DialUDP(ctx, addr)
}
