package server

import "net"

func (s *RulebasedSocks5Server) selectProxyServer(host string) (server *Server, group string, err error) {
	ip := net.ParseIP(host)
	if ip != nil {
		c, _err := s.geoip2db.Country(ip)
		if _err != nil {
			err = _err
			return
		}

		if len(c.Country.IsoCode) == 0 {
			return
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

		return
	}

	if len(s.groups) > 0 {
		for _, g := range s.groups {
			if g.ruleset.SpecialMatch(host) {
				return selectServer(g.servers), g.name, nil
			}
		}

		for _, g := range s.groups {
			if g.ruleset.WildcardMatch(host) {
				return selectServer(g.servers), g.name, nil
			}
		}
	}

	for _, s := range s.servers {
		if s.ruleset.SpecialMatch(host) {
			return s, "", nil
		}
	}

	for _, s := range s.servers {
		if s.ruleset.WildcardMatch(host) {
			return s, "", nil
		}
	}
	return
}
