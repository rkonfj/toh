package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"github.com/rkonfj/toh/client"
	D "github.com/rkonfj/toh/dns"
	"github.com/rkonfj/toh/ruleset"
	"github.com/rkonfj/toh/socks5"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type Options struct {
	// config from file
	Cfg Config
	// socks5+http listen address (specify this to override from config)
	Listen string
	// data root directory. i.e. $HOME/.config/toh
	DataRoot string
	// when using socks5 proxy dns query, if the query dns is consistent with the fake ip
	// the query request will be processed by the built-in local dns
	DNSFake []string
	// build-in local dns listen address
	DNSListen string
	// build-in local dns used upstream dns
	DNSUpstream string
	// how often query results are completely removed from the cache
	DNSEvict time.Duration
}

type S5Server struct {
	server                     *socks5.Socks5Server
	dns                        *D.LocalDNS
	opts                       Options
	servers                    servers
	groups                     []*Group
	defaultDialer              net.Dialer
	geoip2db                   *geoip2.Reader
	localNetIPv4, localNetIPv6 bool
}

func NewS5Server(opts Options) (s5Server *S5Server, err error) {
	opts.Cfg.applyDefaults()
	s5Server = &S5Server{
		opts:          opts,
		servers:       []*Server{},
		groups:        []*Group{},
		defaultDialer: net.Dialer{},
		localNetIPv4:  true,
		localNetIPv6:  true,
	}

	err = s5Server.buildCoreServer()
	if err != nil {
		return
	}

	// use proxy server to exchange dns message
	s5Server.dns = D.NewLocalDNS(D.Options{
		Listen:   opts.DNSListen,
		Upstream: opts.DNSUpstream,
		Evict:    opts.DNSEvict,
		Exchange: s5Server.dnsExchange,
	})

	err = s5Server.loadServers()
	if err != nil {
		return
	}

	err = s5Server.loadGroups()
	if err != nil {
		return
	}
	ruleset.ResetCache()
	s5Server.printRulesetStats()

	logrus.Infof("total loaded %d proxy servers and %d groups",
		len(s5Server.servers), len(s5Server.groups))
	return
}

func (s *S5Server) buildCoreServer() (err error) {
	socks5Opts := socks5.Options{
		Listen:               s.opts.Cfg.Listen,
		TCPDialContext:       s.dialTCP,
		UDPDialContext:       s.dialUDP,
		TrafficEventConsumer: logTrafficEvent,
	}

	if s.opts.Cfg.Advertise != nil {
		socks5Opts.AdvertiseIP = s.opts.Cfg.Advertise.IP
		socks5Opts.AdvertisePort = s.opts.Cfg.Advertise.Port
	}

	// overwrite config from command line flag
	if len(s.opts.Listen) > 0 {
		socks5Opts.Listen = s.opts.Listen
	}

	s.server, err = socks5.NewSocks5Server(socks5Opts)
	if err != nil {
		return
	}
	s.server.HttpServer().Route("/localnet", s.handleLocalNet)
	s.server.HttpServer().Route("/servers", s.handleListServers)
	s.server.HttpServer().Route("/groups", s.handleListGroups)
	s.server.HttpServer().Route("/outbound", s.handleOutbound)
	return
}

func (s *S5Server) Run() error {
	go s.openGeoip2()
	go s.dns.Run()
	go s.watchSignal()
	go s.localAddrFamilyDetection()
	return s.server.Run()
}

func (s *S5Server) loadServers() (err error) {
	for _, srv := range s.opts.Cfg.Servers {
		var c *client.TohClient
		opts := client.Options{
			Server:  srv.Addr,
			Key:     srv.Key,
			Headers: srv.Headers,
		}
		if len(srv.Keepalive) > 0 {
			opts.Keepalive, err = time.ParseDuration(srv.Keepalive)
			if err != nil {
				return
			}
		}
		c, err = client.NewTohClient(opts)
		if err != nil {
			return
		}

		server := &Server{
			name:        srv.Name,
			client:      c,
			latency:     5 * time.Minute,
			latencyIPv6: 5 * time.Minute,
			httpClient: &http.Client{
				Timeout:   5 * time.Minute,
				Transport: &http.Transport{DialContext: c.DialContext},
			},
			httpIPv4: &http.Client{
				Timeout: 6 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return c.DialContext(ctx, "tcp4", addr)
					},
				},
			},
			httpIPv6: &http.Client{
				Timeout: 6 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return c.DialContext(ctx, "tcp6", addr)
					},
				},
			},
		}
		if srv.Ruleset != nil {
			server.ruleset, err = ruleset.Parse(srv.Name, s.opts.DataRoot, srv.Ruleset, c.DialContext)
			if err != nil {
				return
			}
		}
		go server.healthcheck(srv.Healthcheck)
		go server.updateStats()
		s.servers = append(s.servers, server)
	}
	return
}

func (s *S5Server) loadGroups() (err error) {
	for _, g := range s.opts.Cfg.Groups {
		group := &Group{
			name:    g.Name,
			servers: []*Server{},
			lb:      g.Loadbalancer,
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
			group.ruleset, err = ruleset.Parse(g.Name, s.opts.DataRoot, g.Ruleset,
				group.servers.bestLatency().client.DialContext)
			if err != nil {
				return
			}
		}
		s.groups = append(s.groups, group)
	}
	return
}

func (s *S5Server) printRulesetStats() {
	for _, s := range s.servers {
		s.ruleset.PrintStats()
	}
	for _, g := range s.groups {
		g.ruleset.PrintStats()
	}
}

func (s *S5Server) dial(ctx context.Context, addr, network string) (
	dialerName string, conn net.Conn, err error) {
	// dial localdns instead of fake dns
	if len(s.opts.DNSFake) > 0 && len(s.opts.DNSUpstream) > 0 {
		for _, fake := range s.opts.DNSFake {
			if strings.Contains(addr, fake) {
				dialerName = "direct"
				conn, err = s.defaultDialer.Dial(network, s.opts.DNSListen)
				return
			}
		}
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	proxy := s.selectProxyServer(host)
	if proxy.err != nil {
		return
	}

	log := logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr)).WithField("net", network)
	if proxy.ok() {
		dialerName = proxy.server.name
		access := addr
		if proxy.reverseResolutionHost != nil {
			access = fmt.Sprintf("%s:%s", *proxy.reverseResolutionHost, port)
		}
		log.Infof("%s using %s", access, proxy.id())
		conn, err = proxy.server.client.DialContext(ctx, network, addr)
		return
	}

	log.Infof("%s using direct", addr)
	dialerName = "direct"
	conn, err = s.defaultDialer.DialContext(ctx, network, addr)
	return
}

func (s *S5Server) dialTCP(ctx context.Context, addr string) (
	dialerName string, conn net.Conn, err error) {
	return s.dial(ctx, addr, "tcp")
}

func (s *S5Server) dialUDP(ctx context.Context, addr string) (
	dialerName string, conn net.Conn, err error) {
	return s.dial(ctx, addr, "udp")
}

func (s *S5Server) dnsExchange(dnServer string, clientAddr string, r *dns.Msg) (resp *dns.Msg, err error) {
	proxy := s.selectDNSProxyServer(strings.Trim(r.Question[0].Name, "."))
	if proxy.err != nil {
		err = proxy.err
		return
	}
	log := logrus.WithField(spec.AppAddr.String(), clientAddr).WithField("net", "dns")
	if proxy.ok() {
		log.Infof("%s%s using %s", r.Question[0].Name,
			dns.Type(r.Question[0].Qtype).String(), proxy.id())
		if r.Question[0].Qtype == dns.TypeAAAA {
			if !proxy.server.ipv6Enabled() {
				resp = &dns.Msg{}
				resp.Question = r.Question
				resp.SetReply(&dns.Msg{})
				return
			}
		}
		if r.Question[0].Qtype == dns.TypeA {
			if !proxy.server.ipv4Enabled() {
				resp = &dns.Msg{}
				resp.Question = r.Question
				resp.SetReply(&dns.Msg{})
				return
			}
		}
		resp, proxy.err = proxy.server.client.DNSExchange(dnServer, r)
		if proxy.err != nil {
			err = proxy.err
			return
		}
		return
	}
	log.Infof("%s%s using direct", r.Question[0].Name, dns.Type(r.Question[0].Qtype).String())
	if r.Question[0].Qtype == dns.TypeAAAA {
		if !s.localNetIPv6 {
			resp = &dns.Msg{}
			resp.Question = r.Question
			resp.SetReply(&dns.Msg{})
			return
		}
	}
	if r.Question[0].Qtype == dns.TypeA {
		if !s.localNetIPv4 {
			resp = &dns.Msg{}
			resp.Question = r.Question
			resp.SetReply(&dns.Msg{})
			return
		}
	}
	return
}

func (s *S5Server) openGeoip2() {
	geoip2Path := s.opts.Cfg.Geoip2
	if !filepath.IsAbs(geoip2Path) {
		geoip2Path = filepath.Join(s.opts.DataRoot, geoip2Path)
	}

	db, err := geoip2.Open(geoip2Path)
	if err != nil {
		if strings.Contains(err.Error(), "invalid MaxMind") {
			os.Remove(geoip2Path)
		} else if !errors.Is(err, os.ErrNotExist) {
			logrus.Errorf("geoip2 open faild: %s", err.Error())
			return
		}
		downloadGeoip2DB(s.servers.bestLatency().httpClient, geoip2Path)
		s.openGeoip2()
		return
	}
	s.geoip2db = db
}

// watchSignal handle user signal
func (s *S5Server) watchSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	for {
		sig := <-sigs
		switch sig {
		case syscall.SIGHUP: // reload ruleset
			s.reloadRuleset()
		default:
		}
	}
}

func (s *S5Server) reloadRuleset() {
	for _, g := range s.groups {
		err := g.ruleset.Reload()
		if err != nil {
			logrus.Error(err)
		}
	}
	for _, s := range s.servers {
		err := s.ruleset.Reload()
		if err != nil {
			logrus.Error(err)
		}
	}
	ruleset.ResetCache()
	s.printRulesetStats()
}

// localAddrFamilyDetection detect local network address family
func (s *S5Server) localAddrFamilyDetection() {
	if s.opts.Cfg.LocalNet == nil {
		return
	}
	if len(s.opts.Cfg.LocalNet.AddrFamilyDetectURL) == 0 {
		return
	}

	httpIPv4 := newHTTPClient(D.LookupIP4)
	httpIPv6 := newHTTPClient(D.LookupIP6)

	for {
		var err error
		for _, url := range s.opts.Cfg.LocalNet.AddrFamilyDetectURL {
			_, err = httpIPv4.Get(url)
			if err == nil {
				s.localNetIPv4 = true
				break
			}
		}
		if err != nil {
			s.localNetIPv4 = false
		}

		for _, url := range s.opts.Cfg.LocalNet.AddrFamilyDetectURL {
			_, err = httpIPv6.Get(url)
			if err == nil {
				s.localNetIPv6 = true
				break
			}
		}
		if err != nil {
			s.localNetIPv6 = false
		}

		time.Sleep(30 * time.Second)
	}
}

func newHTTPClient(lookupIP func(host string) (ips []net.IP, err error)) *http.Client {
	dialer := net.Dialer{}
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return
				}
				ips, err := lookupIP(host)
				if err != nil {
					return
				}
				return dialer.DialContext(ctx, network,
					net.JoinHostPort(ips[rand.Intn(len(ips))].String(), port))
			},
		},
	}
}

// downloadGeoip2DB download geoip2 db from github
func downloadGeoip2DB(hc *http.Client, geoip2Path string) {
	logrus.Infof("downloading %s (this can take up to %s)", geoip2Path, hc.Timeout)
	mmdbURL := "https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb"
	resp, err := hc.Get(mmdbURL)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer resp.Body.Close()
	mmdb, err := os.OpenFile(geoip2Path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("open db %s error: %s", geoip2Path, err)
		return
	}
	defer mmdb.Close()
	_, err = io.Copy(mmdb, resp.Body)
	if err != nil {
		logrus.Error("download country.mmdb error: ", err)
		return
	}
	logrus.Info("download country.mmdb successfully")
}
