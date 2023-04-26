package s5

import (
	"os"
	"path/filepath"

	"github.com/rkonfj/toh/cmd/s5/server"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:     "s5",
		Short:   "Socks5 proxy server act as ToH client",
		Args:    cobra.NoArgs,
		PreRunE: initAction,
		RunE:    startAction,
	}
	Cmd.Flags().StringP("config", "c", "", "socks5 server config file (default is $HOME/.config/toh/socks5.yml)")
	Cmd.Flags().String("dns", "", "dns to use (enable local dns when not empty)")
	Cmd.Flags().String("dns-listen", "0.0.0.0:2053", "local dns")
	Cmd.Flags().String("dns-proxy", "", "leave blank to randomly choose one from the config server section")
}

func initAction(cmd *cobra.Command, args []string) error {
	logLevel, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return err
	}
	ll, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(ll)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, DisableColors: true})
	return nil
}

func startAction(cmd *cobra.Command, args []string) error {
	opts, err := processOptions(cmd)
	if err != nil {
		return err
	}
	go server.StartDomainNameServer(opts.dns, opts.dnsListen, opts.dnsProxy, opts.cfg)
	sm, err := server.NewSocks5Server(opts.datapath, opts.cfg)
	if err != nil {
		return err
	}
	return sm.Run()
}

type Options struct {
	cfg       server.Config
	datapath  string
	dns       string
	dnsListen string
	dnsProxy  string
}

func processOptions(cmd *cobra.Command) (opts Options, err error) {
	opts.dns, err = cmd.Flags().GetString("dns")
	if err != nil {
		return
	}
	opts.dnsListen, err = cmd.Flags().GetString("dns-listen")
	if err != nil {
		return
	}

	opts.dnsProxy, err = cmd.Flags().GetString("dns-proxy")
	if err != nil {
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	defer func() {
		opts.datapath = filepath.Join(homeDir, ".config", "toh")
	}()
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return
	}
	var configF *os.File
	if configPath != "" {
		configF, err = os.Open(configPath)
		if err != nil {
			return
		}
		opts.cfg = server.Config{}
		err = yaml.NewDecoder(configF).Decode(&opts.cfg)
		return
	}

	configPath = filepath.Join(homeDir, ".config", "toh", "socks5.yml")
	configF, err = os.Open(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
		logrus.Infof("initializing config file %s", configPath)
		err = os.MkdirAll(filepath.Join(homeDir, ".config", "toh"), 0755)
		if err != nil {
			return
		}
		configF, err = os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		opts.cfg = *defaultOptions()
		enc := yaml.NewEncoder(spec.NewConfigWriter(configF))
		enc.SetIndent(2)
		err = enc.Encode(opts.cfg)
		return
	}
	opts.cfg = server.Config{}
	err = yaml.NewDecoder(configF).Decode(&opts.cfg)
	return
}

func defaultOptions() *server.Config {
	return &server.Config{
		Geoip2: "country.mmdb",
		Listen: "0.0.0.0:2080",
		Servers: []server.TohServer{{
			Name:    "us1",
			Api:     "wss://us-l4-vultr.synf.in/ws",
			Key:     "5868a941-3025-4c6d-ad3a-41e29bb42e5f",
			Ruleset: []string{"https://raw.githubusercontent.com/rkonfj/toh/main/ruleset.txt"},
		}},
	}
}
