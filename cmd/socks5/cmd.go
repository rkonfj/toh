package socks5_cmd

import (
	"os"
	"path/filepath"

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
	opts, err := processOptions(cmd)
	if err != nil {
		return err
	}
	sm, err := NewSocks5Server(opts)
	if err != nil {
		return err
	}
	return sm.Run()
}

func processOptions(cmd *cobra.Command) (opts *Options, err error) {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return
	}
	var optsF *os.File
	if configPath != "" {
		optsF, err = os.Open(configPath)
		if err != nil {
			return nil, err
		}
		opts = &Options{}
		err = yaml.NewDecoder(optsF).Decode(opts)
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath = filepath.Join(homeDir, ".config", "toh", "socks5.yml")
	optsF, err = os.Open(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		err = os.MkdirAll(filepath.Join(homeDir, ".config", "toh"), 0644)
		if err != nil {
			return nil, err
		}
		optsF, err = os.OpenFile(configPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		opts = &Options{
			Listen: "0.0.0.0:2080",
			Servers: []TohServer{{
				Name:    "sys",
				Api:     "wss://us-l4-vultr.synf.in/ws",
				Key:     "5868a941-3025-4c6d-ad3a-41e29bb42e5f",
				Ruleset: "https://toh.synf.in/rules/program.txt",
			}},
		}
		err = yaml.NewEncoder(optsF).Encode(opts)
		return
	}

	opts = &Options{}
	err = yaml.NewDecoder(optsF).Decode(opts)
	return
}
