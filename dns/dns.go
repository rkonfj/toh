package dns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

var (
	ErrLocalDNSDisabled = errors.New("local dns is disabled")
)

// Options local dns server options
type Options struct {
	Listen   string                                                                              // listen address
	Upstream string                                                                              // upstream dns server
	Evict    time.Duration                                                                       // cache evict duration
	Exchange func(upstream string, clientAddr string, query *dns.Msg) (resp *dns.Msg, err error) // dns message exchange function
}

// LocalDNS local dns server
// it has a simple dns cache, and can customize dns message exchange function
type LocalDNS struct {
	client      *dns.Client
	cache       *dnsCache
	cacheTicker *time.Ticker
	opts        Options
	enabled     bool
}

func NewLocalDNS(opts Options) *LocalDNS {
	return &LocalDNS{
		client: &dns.Client{},
		cache: &dnsCache{
			cache:     make(map[string]*cacheEntry),
			hostCache: make(map[string]*hostCacheEntry),
		},
		cacheTicker: time.NewTicker(
			time.Duration(math.Max(float64(opts.Evict/20), float64(time.Minute)))),
		opts: opts,
	}
}

// dnsCacheEvictLoop evict expired dns cache
func (c *LocalDNS) dnsCacheEvictLoop() {
	for range c.cacheTicker.C {
		expiredKeys := []string{}
		c.cache.lock.Lock()
		for k, v := range c.cache.cache {
			if time.Now().After(v.expire.Add(c.opts.Evict)) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		for _, k := range expiredKeys {
			delete(c.cache.cache, k)
		}
		expiredKeys = []string{}
		for k, v := range c.cache.hostCache {
			if time.Now().After(v.expire.Add(c.opts.Evict)) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		for _, k := range expiredKeys {
			delete(c.cache.hostCache, k)
		}
		c.cache.lock.Unlock()
	}
}

// Run run the local dns server
func (s *LocalDNS) Run() {
	if len(s.opts.Upstream) == 0 {
		return
	}
	if net.ParseIP(s.opts.Upstream) != nil {
		s.opts.Upstream = net.JoinHostPort(s.opts.Upstream, "53")
	}
	if net.ParseIP(s.opts.Listen) != nil {
		s.opts.Listen += net.JoinHostPort(s.opts.Listen, "53")
	}
	logrus.Infof("listen on %s for %s now", s.opts.Listen, s.opts.Upstream)
	udpServer := &dns.Server{Addr: s.opts.Listen, Net: "udp"}
	tcpServer := &dns.Server{Addr: s.opts.Listen, Net: "tcp"}
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
	s.enabled = true
	wg.Wait()
}

// LookupIP lookup ip address for a host use custom exchange function
func (s *LocalDNS) LookupIP(host string,
	exchange func(dnServer string, query *dns.Msg) (resp *dns.Msg, err error)) (ips []net.IP, err error) {
	if !s.enabled {
		err = ErrLocalDNSDisabled
		return
	}
	r4 := &dns.Msg{}
	r4.SetQuestion(dns.Fqdn(host), dns.TypeA)
	r6 := &dns.Msg{}
	r6.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)

	var wg sync.WaitGroup
	entry4, ok := s.cache.get(r4.Question[0].String())
	if !ok {
		logrus.Debugf("dns lookup %s: ipv4 missed cache", host)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := exchange(s.opts.Upstream, r4)
			if err != nil {
				fmt.Println(err)
				return
			}
			entry4 = s.cacheResponse(r4, resp)
		}()
	}

	entry6, ok := s.cache.get(r6.Question[0].String())
	if !ok {
		logrus.Debugf("dns lookup %s: ipv6 missed cache", host)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := exchange(s.opts.Upstream, r6)
			if err != nil {
				fmt.Println(err)
				return
			}
			entry6 = s.cacheResponse(r6, resp)
		}()
	}
	wg.Wait()

	if entry4 != nil {
		for _, a := range entry4.response.Answer {
			if a.Header().Rrtype == dns.TypeA {
				ips = append(ips, a.(*dns.A).A)
			}
		}
	}
	if entry6 != nil {
		for _, a := range entry6.response.Answer {
			if a.Header().Rrtype == dns.TypeAAAA {
				ips = append(ips, a.(*dns.AAAA).AAAA)
			}
		}
	}
	if len(ips) == 0 {
		err = spec.ErrDNSRecordNotFound
		return
	}
	logrus.Debugf("dns lookup %s: %s", host, ips)
	return
}

// ReverseLookup reverse lookup hostnames for an ip address
func (s *LocalDNS) ReverseLookup(ip string) (hosts []string, err error) {
	if !s.enabled {
		err = ErrLocalDNSDisabled
		return
	}
	hosts, ok := s.cache.hosts(ip)
	if !ok {
		err = errors.New("unresolved")
	}
	return
}

func (s *LocalDNS) dnsQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	if len(r.Question) > 1 {
		logrus.Info("multiple DNS questions are not supported")
	}
	entry, ok := s.cache.get(r.Question[0].String())
	if ok {
		entry.response.Id = r.Id
		w.WriteMsg(entry.response)
		if time.Now().After(entry.expire) {
			go s.updateCache(r, w.RemoteAddr().String())
		}
		return
	}

	entry = s.updateCache(r, w.RemoteAddr().String())
	if entry != nil {
		entry.response.Id = r.Id
		w.WriteMsg(entry.response)
	}
}

func (s *LocalDNS) updateCache(r *dns.Msg, clientAddr string) *cacheEntry {
	resp, err := s.opts.Exchange(s.opts.Upstream, clientAddr, r)
	if err != nil {
		logrus.Error(err)
		return nil
	}

	if resp == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resp, _, err = s.client.ExchangeContext(ctx, r, s.opts.Upstream)
		if err != nil {
			logrus.Error(err)
			return nil
		}
	}

	return s.cacheResponse(r, resp)
}

func (s *LocalDNS) cacheResponse(req, resp *dns.Msg) *cacheEntry {
	maxTTL := 0
	for _, ans := range resp.Answer {
		if int(ans.Header().Ttl) > maxTTL {
			maxTTL = int(ans.Header().Ttl)
		}
	}
	entry := &cacheEntry{
		response: resp,
		expire:   time.Now().Add(time.Duration(maxTTL) * time.Second),
	}
	s.cache.set(req.Question[0].String(), entry)
	return entry
}

type cacheEntry struct {
	response *dns.Msg
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

func (c *dnsCache) hosts(ip string) ([]string, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if entry, ok := c.hostCache[ip]; ok {
		return entry.hosts, ok
	}
	return nil, false
}

func (c *dnsCache) get(key string) (*cacheEntry, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	entry, ok := c.cache[key]
	return entry, ok
}

func (c *dnsCache) set(key string, entry *cacheEntry) {
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
