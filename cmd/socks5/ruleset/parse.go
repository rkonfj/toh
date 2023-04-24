package ruleset

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Ruleset struct {
	proxy       string
	specialSet  []string
	directSet   []string
	wildcardSet []string
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
		if r, ok := strings.CutPrefix(l, "||"); ok {
			rs.specialSet = append(rs.specialSet, strings.Trim(r, "\n"))
			continue
		}
		if _, ok := strings.CutPrefix(l, "|"); ok {
			continue
		}
		if r, ok := strings.CutPrefix(l, "@@"); ok {
			rs.directSet = append(rs.directSet, strings.Trim(r, "\n"))
			continue
		}
		if _, ok := strings.CutPrefix(l, "!"); ok {
			continue
		}
		if strings.Trim(l, "\n") == "" {
			logrus.Info("empty string occered")
		}
		rs.wildcardSet = append(rs.wildcardSet, strings.Trim(l, "\n"))
	}
	logrus.Infof("ruleset %s: special %d, direct %d, wildcard %d",
		name, len(rs.specialSet), len(rs.directSet), len(rs.wildcardSet))
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
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(url)
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
