package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rkonfj/toh/client"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type cacheEntry struct {
	Response dns.Msg
	Expire   time.Time
}

type DomainNameServer struct {
	cacheLock   sync.RWMutex
	cache       map[string]*cacheEntry
	cacheTicker *time.Ticker
	remoteDNS   string
	listen      string
	tohCliet    *client.TohClient
	tohName     string
	dnsClient   *dns.Client
}

func NewDomainNameServer(remoteDNS, listen, proxy string, cfg Config) (s *DomainNameServer, err error) {
	if len(remoteDNS) == 0 {
		err = errors.New("remote dns is empty")
		return
	}
	if len(cfg.Servers) == 0 {
		err = errors.New("proxy servers is empty")
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
			err = fmt.Errorf("proxy server %s not found in config file", proxy)
			return
		}
	}
	if net.ParseIP(remoteDNS) != nil {
		remoteDNS = remoteDNS + ":53"
	}
	if net.ParseIP(listen) != nil {
		listen += ":53"
	}

	c, err := client.NewTohClient(client.Options{
		ServerAddr: server.Api,
		ApiKey:     server.Key,
	})

	if err != nil {
		return
	}

	s = &DomainNameServer{
		cacheLock:   sync.RWMutex{},
		cache:       make(map[string]*cacheEntry),
		cacheTicker: time.NewTicker(10 * time.Minute),
		remoteDNS:   remoteDNS,
		listen:      listen,
		tohCliet:    c,
		tohName:     server.Name,
		dnsClient:   &dns.Client{},
	}
	return
}

func (c *DomainNameServer) get(key string) (*cacheEntry, bool) {
	c.cacheLock.RLock()
	defer c.cacheLock.RUnlock()
	entry, ok := c.cache[key]
	return entry, ok
}

func (c *DomainNameServer) set(key string, entry *cacheEntry) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	c.cache[key] = entry
}

func (c *DomainNameServer) evictCacheLoop() {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	for range c.cacheTicker.C {
		expiredKeys := []string{}
		for k, v := range c.cache {
			if time.Now().After(v.Expire.Add(24 * time.Hour)) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		for _, k := range expiredKeys {
			c.cache[k] = nil
		}
	}
}

func (s *DomainNameServer) Run() {
	logrus.Infof("listen on %s for %s now (%s as proxy)", s.listen, s.remoteDNS, s.tohName)
	udpServer := &dns.Server{Addr: s.listen, Net: "udp"}
	tcpServer := &dns.Server{Addr: s.listen, Net: "tcp"}
	udpServer.Handler = dns.HandlerFunc(s.query)
	tcpServer.Handler = dns.HandlerFunc(s.query)
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
	go s.evictCacheLoop()
	wg.Wait()
}

func (s *DomainNameServer) query(w dns.ResponseWriter, r *dns.Msg) {
	entry, ok := s.get(r.Question[0].String())
	if ok {
		entry.Response.Id = r.Id
		w.WriteMsg(&entry.Response)
		if time.Now().After(entry.Expire) {
			go s.updateCache(r)
		}
		return
	}

	ce := s.updateCache(r)
	if ce != nil {
		ce.Response.Id = r.Id
		w.WriteMsg(&ce.Response)
	}
}

func (s *DomainNameServer) updateCache(r *dns.Msg) *cacheEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := s.tohCliet.DialUDP(ctx, s.remoteDNS)
	if err != nil {
		logrus.Error(err)
		return nil
	}
	defer c.Close()

	resp, _, err := s.dnsClient.ExchangeWithConn(r, &dns.Conn{Conn: &spec.PacketConnWrapper{Conn: c}})
	if err != nil {
		logrus.Error(err)
		return nil
	}

	maxTTL := 0
	for _, ans := range resp.Answer {
		if int(ans.Header().Ttl) > maxTTL {
			maxTTL = int(ans.Header().Ttl)
		}
	}
	ce := &cacheEntry{
		Response: *resp,
		Expire:   time.Now().Add(time.Duration(maxTTL) * time.Second),
	}
	s.set(r.Question[0].String(), ce)
	return ce
}
