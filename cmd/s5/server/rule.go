package server

import (
	"net"
)

func (s *RulebasedSocks5Server) selectProxyServer(host string) (server *Server, group string, err error) {
	ip := net.ParseIP(host)
	if ip != nil {
		// reverse resolution
		if hosts, ok := s.dnsCache.Hosts(ip.String()); ok {
			for _, host := range hosts {
				server, group, err = s.domainMatch(host)
				if server != nil || err != nil {
					return
				}
			}
		}

		// reverse resolution falied and use geoip
		c, _err := s.geoip2db.Country(ip)
		if _err != nil {
			err = _err
			return
		}

		if len(c.Country.IsoCode) == 0 {
			goto domainMatch
		}

		if len(s.groups) > 0 {
			for _, g := range s.groups {
				if g.ruleset.CountryMatch(c.Country.IsoCode) {
					return selectServer(g.servers), g.name, nil
				}
			}
		}

		for _, s := range s.servers {
			if s.ruleset.CountryMatch(c.Country.IsoCode) {
				return s, "", nil
			}
		}

	}
domainMatch:
	return s.domainMatch(host)
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
