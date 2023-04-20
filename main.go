package main

import (
	"github.com/rkonfj/toh/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:     "toh",
		Short:   "A tcp over http/ws server daemon",
		Args:    cobra.NoArgs,
		PreRunE: initAction,
		RunE:    startAction,
	}
	cmd.Flags().String("log-level", "info", "logrus logger level")
	cmd.Flags().String("acl", "acl.json", "file path for authentication")
	cmd.Flags().StringP("listen", "l", "0.0.0.0:9986", "http server listen address (ip:port)")

	cmd.Execute()
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
	options, err := processServerOptions(cmd)
	if err != nil {
		return err
	}
	s, err := server.NewTohServer(options)
	if err != nil {
		return err
	}
	s.Run()
	return nil
}

func processServerOptions(cmd *cobra.Command) (options server.Options, err error) {
	options.Listen, err = cmd.Flags().GetString("listen")
	if err != nil {
		return
	}
	options.ACL, err = cmd.Flags().GetString("acl")
	return
}
