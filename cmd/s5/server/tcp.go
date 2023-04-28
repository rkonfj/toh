package server

import (
	"context"
	"net"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

func (s *RulebasedSocks5Server) dialTCP(ctx context.Context, addr string) (dialerName string, conn net.Conn, err error) {
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
					return dialTCPUseServer(ctx, addr, g.name, selectServer(g.servers))
				}
			}
		}

		for _, s := range s.servers {
			if s.ruleset.CountryMatch(c.Country.IsoCode) {
				return dialTCPUseServer(ctx, addr, "", s)
			}
		}

		goto direct
	}

	if len(s.groups) > 0 {
		for _, g := range s.groups {
			if g.ruleset.SpecialMatch(host) {
				return dialTCPUseServer(ctx, addr, g.name, selectServer(g.servers))
			}
		}

		for _, g := range s.groups {
			if g.ruleset.WildcardMatch(host) {
				return dialTCPUseServer(ctx, addr, g.name, selectServer(g.servers))
			}
		}
	}

	for _, s := range s.servers {
		if s.ruleset.SpecialMatch(host) {
			return dialTCPUseServer(ctx, addr, "", s)
		}
	}

	for _, s := range s.servers {
		if s.ruleset.WildcardMatch(host) {
			return dialTCPUseServer(ctx, addr, "", s)
		}
	}

direct:
	logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr)).Infof("%s using direct", addr)
	dialerName = "direct"
	conn, err = s.defaultDialer.DialContext(ctx, "tcp", addr)
	return
}

func dialTCPUseServer(ctx context.Context, addr, groupName string, server *Server) (dialerName string, conn net.Conn, err error) {
	log := logrus.WithField(spec.AppAddr.String(), ctx.Value(spec.AppAddr))
	dialerName = server.name
	if groupName == "" {
		log.Infof("%s using %s latency %s", addr, dialerName, server.latency)
	} else {
		log.Infof("%s using %s.%s latency %s", addr, groupName, dialerName, server.latency)
	}
	conn, err = server.client.DialTCP(ctx, addr)
	return
}
