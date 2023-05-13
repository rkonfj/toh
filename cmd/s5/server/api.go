package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/rkonfj/toh/server/api"
)

type ServerInfo struct {
	Name    string        `json:"name"`
	Latency time.Duration `json:"latency"`
	Limit   *api.Stats    `json:"limit"`
}

type GroupInfo struct {
	Name    string       `json:"name"`
	Servers []ServerInfo `json:"servers"`
}

func (s *S5Server) listServers(w http.ResponseWriter, r *http.Request) {
	servers := make([]ServerInfo, 0)
	for _, ser := range s.servers {
		servers = append(servers, ServerInfo{
			Name:    ser.name,
			Latency: ser.latency,
			Limit:   ser.limit,
		})
	}
	json.NewEncoder(w).Encode(servers)
}

func (s *S5Server) listGroups(w http.ResponseWriter, r *http.Request) {
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
				Latency: ser.latency,
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
