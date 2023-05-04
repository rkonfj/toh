package server

import (
	"fmt"
	"math/rand"
	"net"

	"github.com/rkonfj/toh/cmd/pf"
	"github.com/sirupsen/logrus"
)

func StartDomainNameServer(dns, listen, proxy string, cfg Config) {
	if len(dns) == 0 {
		return
	}
	if len(cfg.Servers) == 0 {
		return
	}
	var server *TohServer
	if len(proxy) == 0 {
		server = &cfg.Servers[rand.Intn(len(cfg.Servers))]
	} else {
		for _, s := range cfg.Servers {
			if s.Name == proxy {
				server = &s
			}
		}
		if server == nil {
			logrus.Errorf("proxy server %s not found in config file", proxy)
			return
		}
	}
	if net.ParseIP(dns) != nil {
		dns = dns + ":53"
	}
	if net.ParseIP(listen) != nil {
		listen += ":53"
	}
	logrus.Infof("server %s is used as dns proxy", server.Name)
	tm, err := pf.NewTunnelManager(pf.Options{
		Forwards: []string{fmt.Sprintf("udp/%s/%s", listen, dns), fmt.Sprintf("tcp/%s/%s", listen, dns)},
		Server:   server.Api,
		ApiKey:   server.Key,
	})
	if err != nil {
		logrus.Error(err)
		return
	}
	tm.Run()
}
