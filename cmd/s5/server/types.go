package server

import (
	"net/http"
	"sort"
	"time"

	"github.com/rkonfj/toh/client"
	"github.com/rkonfj/toh/ruleset"
	"github.com/rkonfj/toh/server/api"
)

type Server struct {
	name        string
	client      *client.TohClient
	httpIPv4    *http.Client
	httpIPv6    *http.Client
	httpClient  *http.Client
	ruleset     *ruleset.Ruleset
	latency     time.Duration
	latencyIPv6 time.Duration
	limit       *api.Stats
}

func (s *Server) limited() bool {
	if s.limit == nil {
		return false
	}
	if s.limit.Status == "" {
		return false
	}
	return s.limit.Status != "ok"
}

func (s *Server) ipv6Enabled() bool {
	return s.latencyIPv6 < s.httpClient.Timeout
}

func (s *Server) ipv4Enabled() bool {
	return s.latency < s.httpClient.Timeout
}

func (s *Server) healthcheck(urls []string) {
	if len(urls) == 0 {
		s.latency = time.Duration(0)
		s.latencyIPv6 = time.Duration(0)
		return
	}
	for {
		var errIPv4, errIPv6 error
		for _, url := range urls {
			t1 := time.Now()
			_, errIPv4 = s.httpIPv4.Get(url)
			if errIPv4 == nil {
				s.latency = time.Since(t1)
				break
			}
		}
		if errIPv4 != nil {
			s.latency = s.httpClient.Timeout
		}

		for _, url := range urls {
			t2 := time.Now()
			_, errIPv6 = s.httpIPv6.Get(url)
			if errIPv6 == nil {
				s.latencyIPv6 = time.Since(t2)
				break
			}
		}
		if errIPv6 != nil {
			s.latencyIPv6 = s.httpClient.Timeout
		}

		time.Sleep(30 * time.Second)
	}
}

func (s *Server) updateStats() {
	for {
		s.limit, _ = s.client.Stats()
		time.Sleep(15 * time.Second)
	}
}

type servers []*Server

// bestLatency select a best latency  proxy server from servers
func (sers servers) bestLatency() *Server {
	var s []*Server
	for _, server := range sers {
		if server.limited() {
			continue
		}
		s = append(s, server)
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].latencyIPv6 == s[j].latencyIPv6 {
			return s[i].latency < s[j].latency
		}
		return s[i].latencyIPv6 < s[j].latencyIPv6
	})
	if len(s) == 0 {
		return sers[0]
	}
	return s[0]
}

type Group struct {
	name    string
	servers servers
	ruleset *ruleset.Ruleset
	lb      string
	next    int
}

func (g *Group) selectServer() *Server {
	switch g.lb {
	case "rr":
		// round robin
		g.next = (g.next + 1) % len(g.servers)
		return g.servers[g.next]
	default:
		// best latency
		return g.servers.bestLatency()
	}
}
