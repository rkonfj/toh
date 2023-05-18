package server

import (
	"math/rand"
	"net"

	"github.com/rkonfj/toh/ruleset"
	"github.com/sirupsen/logrus"
)

type selected struct {
	server                *Server
	group                 string
	err                   error
	reverseResolutionHost *string
}

func (p *selected) ok() bool {
	return p.server != nil
}

func (p *selected) id() string {
	if p.group != "" {
		return p.group + "." + p.server.name
	}
	return p.server.name
}

func (s *S5Server) testDomainOnGroup(host string, group *Group) (proxy selected) {
	ip := net.ParseIP(host)
	if ip != nil && s.geoip2db != nil {
		c, err := s.geoip2db.Country(ip)
		if err != nil {
			proxy.err = err
			return
		}

		if len(c.Country.IsoCode) != 0 {
			if group.ruleset.IfIPCountryMatch(c.Country.IsoCode) {
				proxy.group = group.name
				proxy.server = group.selectServer()
				return
			}
		}
	}
	directs := make(map[string]struct{})
	for _, g := range s.groups {
		if g.ruleset.DirectMatch(host) {
			directs[g.name] = struct{}{}
		}
	}
	if _, ok := directs[group.name]; !ok {
		for _, g := range s.groups {
			if g.ruleset.SpecialMatch(host) {
				proxy.group = g.name
				proxy.server = group.selectServer()
				return
			}
		}
	}
	if group.ruleset.WildcardMatch(host) {
		proxy.group = group.name
		proxy.server = group.selectServer()
		return
	}
	return selected{}
}

func (s *S5Server) testIPOnGroup(host string, group *Group) (proxy selected) {
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := s.dns.LookupIP(host, group.selectServer().client.DNSExchange)
		if err != nil {
			proxy.err = err
			return
		}
		ip = ips[rand.Intn(len(ips))]
	}
	if s.geoip2db != nil {
		c, err := s.geoip2db.Country(ip)
		if err != nil {
			proxy.err = err
			return
		}
		if group.ruleset.CountryMatch(c.Country.IsoCode) {
			proxy.group = group.name
			proxy.server = group.selectServer()
			return
		}
	}
	return selected{}
}

func (s *S5Server) testDomainOnServer(host string, server *Server) (proxy selected) {
	ip := net.ParseIP(host)
	if ip != nil && s.geoip2db != nil {
		c, err := s.geoip2db.Country(ip)
		if err != nil {
			proxy.err = err
			return
		}

		if len(c.Country.IsoCode) != 0 {
			if server.ruleset.IfIPCountryMatch(c.Country.IsoCode) {
				proxy.server = server
				return
			}
		}
	}
	directs := make(map[string]struct{})
	for _, g := range s.groups {
		if g.ruleset.DirectMatch(host) {
			directs[g.name] = struct{}{}
		}
	}
	if _, ok := directs[server.name]; !ok {
		for _, se := range s.servers {
			if se.ruleset.SpecialMatch(host) {
				proxy.server = server
				return
			}
		}
	}
	if server.ruleset.WildcardMatch(host) {
		proxy.server = server
		return
	}
	return selected{}
}

func (s *S5Server) testIPOnServer(host string, server *Server) (proxy selected) {
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := s.dns.LookupIP(host, server.client.DNSExchange)
		if err != nil {
			proxy.err = err
			return
		}
		ip = ips[rand.Intn(len(ips))]
	}
	if s.geoip2db != nil {
		c, err := s.geoip2db.Country(ip)
		if err != nil {
			proxy.err = err
			return
		}
		if server.ruleset.CountryMatch(c.Country.IsoCode) {
			proxy.server = server
			return
		}
	}
	return selected{}
}

func (s *S5Server) selectProxyServer(host string) (proxy selected) {
	// reverse resolution
	if hosts, err := s.dns.ReverseLookup(host); err == nil {
		host = hosts[0]
		proxy.reverseResolutionHost = &hosts[0]
	}

	if len(s.groups) > 0 {
		for _, group := range s.groups {
			logrus.Debugf("group %s using match strategy %d", group.name, group.ruleset.MatchStrategy())
			switch group.ruleset.MatchStrategy() {
			case ruleset.IPIfNonDomainMatch:
				// domainMatch and return
				proxy = s.testDomainOnGroup(host, group)
				if proxy.server != nil {
					return
				}
				// ipMatch and return
				proxy = s.testIPOnGroup(host, group)
				if proxy.server != nil {
					return
				}
			case ruleset.OnlyDomainMatch:
				// domainMatch and return
				proxy = s.testDomainOnGroup(host, group)
				if proxy.server != nil {
					return
				}
			case ruleset.OnlyIPMatch:
				// ipMatch and return
				proxy = s.testIPOnGroup(host, group)
				if proxy.server != nil {
					return
				}
			default:
				continue
			}
		}
	}

	for _, server := range s.servers {
		logrus.Debugf("server %s using match strategy %d", server.name, server.ruleset.MatchStrategy())
		switch server.ruleset.MatchStrategy() {
		case ruleset.IPIfNonDomainMatch:
			// domainMatch and return
			proxy = s.testDomainOnServer(host, server)
			if proxy.server != nil {
				return
			}
			// ipMatch and return
			proxy = s.testIPOnServer(host, server)
			if proxy.server != nil {
				return
			}
		case ruleset.OnlyDomainMatch:
			// domainMatch and return
			proxy = s.testDomainOnServer(host, server)
			if proxy.server != nil {
				return
			}
		case ruleset.OnlyIPMatch:
			// ipMatch and return
			proxy = s.testIPOnServer(host, server)
			if proxy.server != nil {
				return
			}
		default:
			continue
		}
	}
	proxy.server = nil
	return
}

// selectDNSProxyServer use ruleset.OnlyDomainMatch or random server
func (s *S5Server) selectDNSProxyServer(host string) (proxy selected) {
	if len(s.groups) > 0 {
		for _, group := range s.groups {
			proxy = s.testDomainOnGroup(host, group)
			if proxy.server != nil {
				return
			}
		}
	}

	for _, server := range s.servers {
		proxy = s.testDomainOnServer(host, server)
		if proxy.server != nil {
			return
		}
	}
	proxy.server = selectServer(s.servers)
	return
}
