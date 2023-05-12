package server

import (
	"net"
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

func newSelected(server *Server, group string, err error) *selected {
	return &selected{
		server: server,
		group:  group,
		err:    err,
	}
}

func (s *RulebasedSocks5Server) selectProxyServer(host string) (proxy *selected) {
	ip := net.ParseIP(host)
	if ip != nil {
		// reverse resolution
		if hosts, ok := s.dnsCache.Hosts(ip.String()); ok {
			for _, host := range hosts {
				proxy = newSelected(s.domainMatch(host))
				proxy.reverseResolutionHost = &host
				if proxy.server != nil || proxy.err != nil {
					return
				}
			}
			return
		}

		// reverse resolution falied and use geoip
		c, err := s.geoip2db.Country(ip)
		if err != nil {
			proxy.err = err
			return
		}

		if len(c.Country.IsoCode) == 0 {
			goto domainMatch
		}

		if len(s.groups) > 0 {
			for _, g := range s.groups {
				if g.ruleset.CountryMatch(c.Country.IsoCode) {
					proxy = newSelected(selectServer(g.servers), g.name, nil)
					return
				}
			}
		}

		for _, s := range s.servers {
			if s.ruleset.CountryMatch(c.Country.IsoCode) {
				proxy = newSelected(s, "", nil)
				return
			}
		}

	}
domainMatch:
	proxy = newSelected(s.domainMatch(host))
	return
}

func (s *RulebasedSocks5Server) domainMatch(host string) (server *Server, group string, err error) {
	// if group match, return
	if len(s.groups) > 0 {
		directGroups := make(map[string]struct{})
		for _, g := range s.groups {
			if g.ruleset.DirectMatch(host) {
				directGroups[g.name] = struct{}{}
			}
		}
		for _, g := range s.groups {
			if _, ok := directGroups[g.name]; ok {
				continue
			}
			if g.ruleset.SpecialMatch(host) {
				return selectServer(g.servers), g.name, nil
			}
		}

		for _, g := range s.groups {
			if _, ok := directGroups[g.name]; ok {
				continue
			}
			if g.ruleset.WildcardMatch(host) {
				return selectServer(g.servers), g.name, nil
			}
		}
	}

	// else, match server and return
	directServers := make(map[string]struct{})
	for _, s := range s.servers {
		if s.ruleset.DirectMatch(host) {
			directServers[s.name] = struct{}{}
		}
	}

	for _, s := range s.servers {
		if _, ok := directServers[s.name]; ok {
			continue
		}
		if s.ruleset.SpecialMatch(host) {
			return s, "", nil
		}
	}

	for _, s := range s.servers {
		if _, ok := directServers[s.name]; ok {
			continue
		}
		if s.ruleset.WildcardMatch(host) {
			return s, "", nil
		}
	}
	return
}
