package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/rkonfj/toh/server/api"
)

type ServerInfo struct {
	Name    string     `json:"name"`
	Latency *Latency   `json:"latency"`
	Limit   *api.Stats `json:"limit"`
}

type Latency struct {
	IPv4 time.Duration `json:"ipv4"`
	IPv6 time.Duration `json:"ipv6"`
}

type GroupInfo struct {
	Name    string       `json:"name"`
	Servers []ServerInfo `json:"servers"`
}

type OutboundInfo struct {
	Group  string     `json:"group"`
	Server ServerInfo `json:"server"`
	Error  string     `json:"error"`
}

type LocalNetInfo struct {
	IPv6 bool `json:"ipv6"`
	IPv4 bool `json:"ipv4"`
}

func (s *S5Server) handleLocalNet(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(LocalNetInfo{IPv6: s.localNetIPv6, IPv4: s.localNetIPv4})
}

func (s *S5Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers := make([]ServerInfo, 0)
	for _, ser := range s.servers {
		servers = append(servers, ServerInfo{
			Name:    ser.name,
			Latency: &Latency{IPv4: ser.latency, IPv6: ser.latencyIPv6},
			Limit:   ser.limit,
		})
	}
	json.NewEncoder(w).Encode(servers)
}

func (s *S5Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups := make([]GroupInfo, 0)

	for _, g := range s.groups {
		var servers []ServerInfo
		s := make([]*Server, len(g.servers))
		copy(s, g.servers)
		sort.Slice(s, func(i, j int) bool {
			return s[i].latency < s[j].latency
		})
		for _, ser := range s {
			servers = append(servers, ServerInfo{
				Name:    ser.name,
				Latency: &Latency{IPv4: ser.latency, IPv6: ser.latencyIPv6},
				Limit:   ser.limit,
			})
		}
		groups = append(groups, GroupInfo{
			Name:    g.name,
			Servers: servers,
		})
	}
	json.NewEncoder(w).Encode(groups)
}

func (s *S5Server) handleOutbound(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	selected := s.selectProxyServer(host)

	outbound := OutboundInfo{
		Group: selected.group,
		Server: ServerInfo{
			Name: "direct",
		},
	}

	if selected.err != nil {
		outbound.Error = selected.err.Error()
	} else if selected.server != nil {
		outbound.Server = ServerInfo{
			Name:    selected.server.name,
			Latency: &Latency{IPv4: selected.server.latency, IPv6: selected.server.latencyIPv6},
			Limit:   selected.server.limit,
		}
	}

	json.NewEncoder(w).Encode(outbound)
}
