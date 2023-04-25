package socks5_cmd

import (
	"os"
	"path/filepath"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:     "socks5",
		Short:   "Socks5 proxy server",
		Args:    cobra.NoArgs,
		PreRunE: initAction,
		RunE:    startAction,
	}
	Cmd.Flags().StringP("config", "c", "", "socks5 server config file (default is $HOME/.config/toh/socks5.yml)")
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
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	return nil
}

func startAction(cmd *cobra.Command, args []string) error {
	opts, dataPath, err := processOptions(cmd)
	if err != nil {
		return err
	}
	sm, err := NewSocks5Server(dataPath, opts)
	if err != nil {
		return err
	}
	return sm.Run()
}

func processOptions(cmd *cobra.Command) (opts *Options, dataPath string, err error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	defer func() {
		dataPath = filepath.Join(homeDir, ".config", "toh")
	}()
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return
	}
	var optsF *os.File
	if configPath != "" {
		optsF, err = os.Open(configPath)
		if err != nil {
			return
		}
		opts = &Options{}
		err = yaml.NewDecoder(optsF).Decode(opts)
		return
	}

	configPath = filepath.Join(homeDir, ".config", "toh", "socks5.yml")
	optsF, err = os.Open(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
		logrus.Infof("initializing config file %s", configPath)
		err = os.MkdirAll(filepath.Join(homeDir, ".config", "toh"), 0755)
		if err != nil {
			return
		}
		optsF, err = os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		opts = defaultOptions()
		enc := yaml.NewEncoder(spec.NewConfigWriter(optsF))
		enc.SetIndent(2)
		err = enc.Encode(opts)
		return
	}
	opts = &Options{}
	err = yaml.NewDecoder(optsF).Decode(opts)
	return
}

func defaultOptions() *Options {
	return &Options{
		Geoip2: "country.mmdb",
		Listen: "0.0.0.0:2080",
		Servers: []TohServer{{
			Name:    "us1",
			Api:     "wss://us-l4-vultr.synf.in/ws",
			Key:     "5868a941-3025-4c6d-ad3a-41e29bb42e5f",
			Ruleset: "https://file.synf.in/toh/rules/default.txt",
		}},
	}
}
