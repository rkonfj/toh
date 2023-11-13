package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/rkonfj/toh/spec"
)

var dnsClient *dns.Client = &dns.Client{}

var DefaultResolver Resolver = Resolver{
	IPv4Servers: []string{"8.8.8.8:53", "223.5.5.5:53"},
	IPv6Servers: []string{"[2001:4860:4860::8888]:53", "[2400:3200::1]:53"},
	Exchange: func(dnServer string, r *dns.Msg) (resp *dns.Msg, err error) {
		dnsLookupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, _, err = dnsClient.ExchangeContext(dnsLookupCtx, r, dnServer)
		return
	},
}

type Resolver struct {
	IPv4Servers []string
	IPv6Servers []string
	Exchange    func(dnServer string, r *dns.Msg) (*dns.Msg, error)
}

func LookupIP4(host string) (ips []net.IP, err error) {
	return DefaultResolver.LookupIP(host, dns.TypeA)
}

func LookupIP6(host string) (ips []net.IP, err error) {
	return DefaultResolver.LookupIP(host, dns.TypeAAAA)
}

func (r *Resolver) LookupIP(host string, t uint16) (ips []net.IP, err error) {
	ip := net.ParseIP(host)
	if ip != nil {
		ips = append(ips, ip)
		return
	}
	query := &dns.Msg{}
	query.SetQuestion(dns.Fqdn(host), t)
	var resp *dns.Msg
	for _, dnServer := range append(r.IPv4Servers, r.IPv6Servers...) {
		resp, err = r.Exchange(dnServer, query)
		if err == nil {
			break
		}
	}
	if err != nil {
		return
	}
	for _, a := range resp.Answer {
		if a.Header().Rrtype == dns.TypeA {
			ips = append(ips, a.(*dns.A).A)
		}
		if a.Header().Rrtype == dns.TypeAAAA {
			ips = append(ips, a.(*dns.AAAA).AAAA)
		}
	}
	if len(ips) == 0 {
		if t == dns.TypeA {
			err = spec.ErrDNSTypeANotFound
		} else if t == dns.TypeAAAA {
			err = spec.ErrDNSTypeAAAANotFound
		} else {
			err = fmt.Errorf("resolve %s : no type %s was found", host, dns.Type(t))
		}
	}
	return
}
