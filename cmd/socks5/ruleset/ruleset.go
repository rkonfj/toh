package ruleset

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type Ruleset struct {
	client           spec.TohClient
	proxy            string
	directCountrySet []string
	proxyCountrySet  []string
	specialSet       []string
	directSet        []string
	wildcardSet      []string
}

func Parse(client spec.TohClient, name string, ruleset []string, datapath string) (rs *Ruleset, err error) {
	rs = &Ruleset{proxy: name, client: client}
	for _, ruleLocation := range ruleset {
		var reader io.Reader
		var readCloser io.ReadCloser
		if r, ok := strings.CutPrefix(ruleLocation, "b64,"); ok {
			if strings.HasPrefix(r, "https") {
				readCloser, err = rs.download(r)
			} else {
				readCloser, err = rs.openFile(ensureAbsPath(datapath, r))
			}
			if err != nil {
				return
			}
			reader = base64.NewDecoder(base64.RawStdEncoding, readCloser)
		} else {
			if strings.HasPrefix(r, "https") {
				readCloser, err = rs.download(r)
				reader = readCloser
			} else {
				readCloser, err = rs.openFile(ensureAbsPath(datapath, r))
				reader = readCloser
			}
			if err != nil {
				return
			}
		}
		err = rs.LoadFromReader(*bufio.NewReader(reader))
		if err != nil {
			readCloser.Close()
			return
		}
		readCloser.Close()
	}
	logrus.Infof("ruleset %s: special %d, direct %d, wildcard %d",
		rs.proxy, len(rs.specialSet), len(rs.directSet), len(rs.wildcardSet))
	if len(rs.directCountrySet) > 0 {
		logrus.Infof("ruleset %s if-ip: direct %s", rs.proxy, rs.directCountrySet)

	} else if len(rs.proxyCountrySet) > 0 {
		logrus.Infof("ruleset %s if-ip: proxy %s", rs.proxy, rs.proxyCountrySet)
	}
	return
}

func (rs *Ruleset) download(ruleLocation string) (reader io.ReadCloser, err error) {
	logrus.Infof("downloading %s", ruleLocation)
	reader, err = readerFromURL(rs.client, ruleLocation)
	if err != nil {
		return
	}
	return
}

func (rs *Ruleset) openFile(ruleLocation string) (reader io.ReadCloser, err error) {
	reader, err = os.Open(ruleLocation)
	if err != nil {
		return
	}
	return
}

func (rs *Ruleset) LoadFromReader(reader bufio.Reader) error {
	for {
		l, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
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
		if r, ok := strings.CutPrefix(l, "@@"); ok {
			rs.directSet = append(rs.directSet, trim(r))
			continue
		}
		if _, ok := strings.CutPrefix(l, "|"); ok {
			continue
		}
		if _, ok := strings.CutPrefix(l, "!"); ok {
			continue
		}
		rs.wildcardSet = append(rs.wildcardSet, trim(l))
	}
	return nil
}

func (rs *Ruleset) SpecialMatch(host string) bool {
	for _, r := range rs.specialSet {
		if host == r || host == fmt.Sprintf("www.%s", r) {
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

func readerFromURL(client spec.TohClient, url string) (io.ReadCloser, error) {
	resp, err := (&http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ipAddr, err := spec.ResolveIP(ctx, client.DialTCP, addr)
				if err != nil {
					if strings.Contains(err.Error(), spec.ErrAuth.Error()) {
						return nil, errors.New("proxy failed, invalid Toh Key")
					}
					return nil, err
				}
				return client.DialTCP(ctx, ipAddr)
			},
		},
	}).Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s", url, resp.Status)
	}
	return resp.Body, nil
}

func trim(s string) string {
	return strings.Trim(strings.Trim(s, "\n"), " ")
}

func ensureAbsPath(datapath, filename string) string {
	if filename == "" {
		return ""
	}
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(datapath, filename)
}
