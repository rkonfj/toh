package ruleset

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type Ruleset struct {
	proxy            string
	directCountrySet []string
	proxyCountrySet  []string
	specialSet       []string
	directSet        []string
	wildcardSet      []string
}

func NewRulesetFromReader(name string, reader io.ReadCloser) (*Ruleset, error) {
	rs := Ruleset{proxy: name, specialSet: []string{}, directSet: []string{}, wildcardSet: []string{}}
	defer reader.Close()
	fR := bufio.NewReader(reader)
	for {
		l, err := fR.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(l) == 0 || len(strings.Trim(l, "\n")) == 0 {
			continue
		}
		if r, ok := strings.CutPrefix(l, "if-ip:direct,"); ok {
			rs.directCountrySet = append(rs.directCountrySet, trim(r))
			continue
		}
		if r, ok := strings.CutPrefix(l, "if-ip:proxy,"); ok {
			rs.proxyCountrySet = append(rs.proxyCountrySet, trim(r))
			continue
		}
		if r, ok := strings.CutPrefix(l, "||"); ok {
			rs.specialSet = append(rs.specialSet, trim(r))
			continue
		}
		if _, ok := strings.CutPrefix(l, "|"); ok {
			continue
		}
		if r, ok := strings.CutPrefix(l, "@@"); ok {
			rs.directSet = append(rs.directSet, trim(r))
			continue
		}
		if _, ok := strings.CutPrefix(l, "!"); ok {
			continue
		}
		if strings.Trim(l, "\n") == "" {
			logrus.Info("empty string occered")
		}
		rs.wildcardSet = append(rs.wildcardSet, trim(l))
	}
	logrus.Infof("ruleset %s domain: special %d, direct %d, wildcard %d",
		name, len(rs.specialSet), len(rs.directSet), len(rs.wildcardSet))
	if len(rs.directCountrySet) > 0 {
		logrus.Infof("ruleset %s if-ip: direct %s", name, rs.directCountrySet)

	} else if len(rs.proxyCountrySet) > 0 {
		logrus.Infof("ruleset %s if-ip: proxy %s", name, rs.proxyCountrySet)
	}
	return &rs, nil
}

func NewRulesetFromFile(name, filename string) (*Ruleset, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	return NewRulesetFromReader(name, f)
}

func NewRulesetFromURL(name, url string) (*Ruleset, error) {
	logrus.Infof("downloading %s for %s ruleset", url, name)
	resp, err := (&http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := net.Dialer{}
				ipAddr, err := spec.ResolveIP(ctx, dialer, addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, ipAddr)
			},
		},
	}).Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s", url, resp.Status)
	}
	return NewRulesetFromReader(name, resp.Body)
}

func (rs *Ruleset) SpecialMatch(host string) bool {
	for _, r := range rs.specialSet {
		if host == r {
			return true
		}
	}

	for _, r := range rs.directSet {
		if host == r {
			return false
		}
	}
	return false
}

func (rs *Ruleset) WildcardMatch(host string) bool {
	for _, r := range rs.wildcardSet {
		if strings.HasSuffix(host, r) || host == strings.Trim(r, ".") {
			logrus.Debugf("%s matched rule [%s]", host, r)
			return true
		}
	}
	return false
}

func (rs *Ruleset) CountryMatch(country string) bool {
	if len(rs.directCountrySet) > 0 {
		return !slices.Contains(rs.directCountrySet, country)
	}
	return slices.Contains(rs.proxyCountrySet, country)
}

func trim(s string) string {
	return strings.Trim(strings.Trim(s, "\n"), " ")
}
