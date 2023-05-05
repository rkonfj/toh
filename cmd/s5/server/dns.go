package server

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type cacheEntry struct {
	Response dns.Msg
	Expire   time.Time
}

func (c *RulebasedSocks5Server) getDNSCahce(key string) (*cacheEntry, bool) {
	c.dnsCacheLock.RLock()
	defer c.dnsCacheLock.RUnlock()
	entry, ok := c.dnsCache[key]
	return entry, ok
}

func (c *RulebasedSocks5Server) setDNSCache(key string, entry *cacheEntry) {
	c.dnsCacheLock.Lock()
	defer c.dnsCacheLock.Unlock()
	c.dnsCache[key] = entry
}

func (c *RulebasedSocks5Server) dnsCacheEvictLoop() {
	for range c.dnsCacheTicker.C {
		expiredKeys := []string{}
		c.dnsCacheLock.Lock()
		for k, v := range c.dnsCache {
			if time.Now().After(v.Expire.Add(c.opts.DNSEvict)) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		for _, k := range expiredKeys {
			delete(c.dnsCache, k)
		}
		c.dnsCacheLock.Unlock()
	}
}

func (s *RulebasedSocks5Server) runDNSIfNeeded() {
	if len(s.opts.DNSUpstream) == 0 {
		return
	}
	if len(s.servers) == 0 {
		return
	}
	if net.ParseIP(s.opts.DNSUpstream) != nil {
		s.opts.DNSUpstream = s.opts.DNSUpstream + ":53"
	}
	if net.ParseIP(s.opts.DNSListen) != nil {
		s.opts.DNSListen += ":53"
	}
	logrus.Infof("listen on %s for %s now", s.opts.DNSListen, s.opts.DNSUpstream)
	udpServer := &dns.Server{Addr: s.opts.DNSListen, Net: "udp"}
	tcpServer := &dns.Server{Addr: s.opts.DNSListen, Net: "tcp"}
	udpServer.Handler = dns.HandlerFunc(s.dnsQuery)
	tcpServer.Handler = dns.HandlerFunc(s.dnsQuery)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		logrus.Error(udpServer.ListenAndServe())
	}()
	go func() {
		defer wg.Done()
		logrus.Error(tcpServer.ListenAndServe())
	}()
	go s.dnsCacheEvictLoop()
	wg.Wait()
}

func (s *RulebasedSocks5Server) dnsQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	if len(r.Question) > 1 {
		logrus.Info("multiple DNS questions are not supported")
	}
	entry, ok := s.getDNSCahce(r.Question[0].String())
	if ok {
		entry.Response.Id = r.Id
		w.WriteMsg(&entry.Response)
		if time.Now().After(entry.Expire) {
			go s.updateCache(r, w.RemoteAddr().String())
		}
		return
	}
	entry = s.updateCache(r, w.RemoteAddr().String())
	if entry != nil {
		entry.Response.Id = r.Id
		w.WriteMsg(&entry.Response)
	}
}

func (s *RulebasedSocks5Server) updateCache(r *dns.Msg, clientAddr string) *cacheEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, group, err := s.selectProxyServer(strings.Trim(r.Question[0].Name, "."))
	if err != nil {
		logrus.Error(err)
		return nil
	}
	var resp *dns.Msg
	log := logrus.WithField(spec.AppAddr.String(), clientAddr)
	if server != nil {
		c, err := server.client.DialUDP(ctx, s.opts.DNSUpstream)
		if err != nil {
			logrus.Error(err)
			return nil
		}
		defer c.Close()
		resp, _, err = s.dnsClient.ExchangeWithConn(r, &dns.Conn{Conn: &spec.PacketConnWrapper{Conn: c}})
		if err != nil {
			logrus.Error(err)
			return nil
		}
		proxyId := server.name
		if group != "" {
			proxyId = group + "." + server.name
		}
		log.Infof("dns query %s type %s using %s latency %s", r.Question[0].Name, dns.Type(r.Question[0].Qtype).String(), proxyId, server.latency)
	} else {
		resp, _, err = s.dnsClient.ExchangeContext(ctx, r, s.opts.DNSUpstream)
		if err != nil {
			logrus.Error(err)
			return nil
		}
		log.Infof("dns query %s type %s using direct", r.Question[0].Name, dns.Type(r.Question[0].Qtype).String())
	}

	maxTTL := 0
	for _, ans := range resp.Answer {
		if int(ans.Header().Ttl) > maxTTL {
			maxTTL = int(ans.Header().Ttl)
		}
	}
	entry := &cacheEntry{
		Response: *resp,
		Expire:   time.Now().Add(time.Duration(maxTTL) * time.Second),
	}
	s.setDNSCache(r.Question[0].String(), entry)
	return entry
}
