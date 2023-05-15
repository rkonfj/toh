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
	response dns.Msg
	expire   time.Time
}

type hostCacheEntry struct {
	hosts  []string
	expire time.Time
}

type dnsCache struct {
	lock      sync.RWMutex
	cache     map[string]*cacheEntry
	hostCache map[string]*hostCacheEntry
}

func (c *dnsCache) Hosts(ip string) ([]string, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if entry, ok := c.hostCache[ip]; ok {
		return entry.hosts, ok
	}
	return nil, false
}

func (c *dnsCache) Get(key string) (*cacheEntry, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	entry, ok := c.cache[key]
	return entry, ok
}

func (c *dnsCache) Set(key string, entry *cacheEntry) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cache[key] = entry
	host := entry.response.Question[0].Name
	for _, a := range entry.response.Answer {
		var ip string
		if a.Header().Rrtype == dns.TypeA {
			ip = a.(*dns.A).A.To4().String()
		} else if a.Header().Rrtype == dns.TypeAAAA {
			ip = a.(*dns.AAAA).AAAA.String()
		}
		if _, ok := c.hostCache[ip]; !ok {
			c.hostCache[ip] = &hostCacheEntry{expire: entry.expire}
		}
		c.hostCache[ip].hosts = append(c.hostCache[ip].hosts, strings.Trim(host, "."))
	}
}

func (c *S5Server) dnsCacheEvictLoop() {
	for range c.dnsCacheTicker.C {
		expiredKeys := []string{}
		c.dnsCache.lock.Lock()
		for k, v := range c.dnsCache.cache {
			if time.Now().After(v.expire.Add(c.opts.DNSEvict)) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		for _, k := range expiredKeys {
			delete(c.dnsCache.cache, k)
		}
		expiredKeys = []string{}
		for k, v := range c.dnsCache.hostCache {
			if time.Now().After(v.expire.Add(c.opts.DNSEvict)) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		for _, k := range expiredKeys {
			delete(c.dnsCache.hostCache, k)
		}
		c.dnsCache.lock.Unlock()
	}
}

func (s *S5Server) runDNSIfNeeded() {
	if len(s.opts.DNSUpstream) == 0 {
		return
	}
	if len(s.servers) == 0 {
		return
	}
	if net.ParseIP(s.opts.DNSUpstream) != nil {
		s.opts.DNSUpstream = net.JoinHostPort(s.opts.DNSUpstream, "53")
	}
	if net.ParseIP(s.opts.DNSListen) != nil {
		s.opts.DNSListen += net.JoinHostPort(s.opts.DNSListen, "53")
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

func (s *S5Server) dnsQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	if len(r.Question) > 1 {
		logrus.Info("multiple DNS questions are not supported")
	}
	entry, ok := s.dnsCache.Get(r.Question[0].String())
	if ok {
		entry.response.Id = r.Id
		w.WriteMsg(&entry.response)
		if time.Now().After(entry.expire) {
			go s.updateCache(r, w.RemoteAddr().String())
		}
		return
	}
	entry = s.updateCache(r, w.RemoteAddr().String())
	if entry != nil {
		entry.response.Id = r.Id
		w.WriteMsg(&entry.response)
	}
}

func (s *S5Server) updateCache(r *dns.Msg, clientAddr string) *cacheEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	proxy := s.selectProxyServer(strings.Trim(r.Question[0].Name, "."))
	if proxy.err != nil {
		logrus.Error(proxy.err)
		return nil
	}
	var resp *dns.Msg
	log := logrus.WithField(spec.AppAddr.String(), clientAddr)
	if proxy.ok() {
		resp, proxy.err = proxy.server.client.DNSExchange(s.opts.DNSUpstream, r)
		if proxy.err != nil {
			logrus.Error(proxy.err)
			return nil
		}
		log.Infof("dns query %s type %s using %s latency %s",
			r.Question[0].Name, dns.Type(r.Question[0].Qtype).String(), proxy.id(), proxy.server.latency)
	} else {
		resp, _, proxy.err = s.dnsClient.ExchangeContext(ctx, r, s.opts.DNSUpstream)
		if proxy.err != nil {
			logrus.Error(proxy.err)
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
		response: *resp,
		expire:   time.Now().Add(time.Duration(maxTTL) * time.Second),
	}
	s.dnsCache.Set(r.Question[0].String(), entry)
	return entry
}
