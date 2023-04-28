package server

import (
	"context"
	"net"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

func (s *RulebasedSocks5Server) dialTCP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
	log := logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr))
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	ip := net.ParseIP(host)
	if ip != nil {
		c, _err := s.geoip2db.Country(ip)
		if _err != nil {
			err = _err
			return
		}

		if len(c.Country.IsoCode) == 0 {
			goto direct
		}

		if len(s.groups) > 0 {
			for _, g := range s.groups {
				if g.ruleset.CountryMatch(c.Country.IsoCode) {
					server := selectServer(g.servers)
					dialerName = server.name
					log.Infof("%s using %s.%s", addr, g.name, dialerName)
					conn, err = server.client.DialTCP(ctx, addr)
					return
				}
			}
		}

		for _, toh := range s.servers {
			if toh.ruleset.CountryMatch(c.Country.IsoCode) {
				log.Infof("%s using %s", addr, toh.name)
				dialerName = toh.name
				conn, err = toh.client.DialTCP(ctx, addr)
				return
			}
		}

		goto direct
	}

	if len(s.groups) > 0 {
		for _, g := range s.groups {
			if g.ruleset.SpecialMatch(host) {
				server := selectServer(g.servers)
				dialerName = server.name
				log.Infof("%s using %s.%s", addr, g.name, dialerName)
				conn, err = server.client.DialTCP(ctx, addr)
				return
			}
		}

		for _, g := range s.groups {
			if g.ruleset.WildcardMatch(host) {
				server := selectServer(g.servers)
				dialerName = server.name
				log.Infof("%s using %s.%s", addr, g.name, dialerName)
				conn, err = server.client.DialTCP(ctx, addr)
				return
			}
		}
	}

	for _, toh := range s.servers {
		if toh.ruleset.SpecialMatch(host) {
			log.Infof("%s using %s", addr, toh.name)
			dialerName = toh.name
			conn, err = toh.client.DialTCP(ctx, addr)
			return
		}
	}

	for _, toh := range s.servers {
		if toh.ruleset.WildcardMatch(host) {
			log.Infof("%s using %s", addr, toh.name)
			dialerName = toh.name
			conn, err = toh.client.DialTCP(ctx, addr)
			return
		}
	}

direct:
	log.Infof("%s using direct", addr)
	dialerName = "direct"
	conn, err = s.defaultDialer.DialContext(ctx, "tcp", addr)
	return
}
