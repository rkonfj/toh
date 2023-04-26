package serve

import (
	"github.com/rkonfj/toh/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:     "serve",
		Short:   "ToH server daemon",
		Args:    cobra.NoArgs,
		PreRunE: initAction,
		RunE:    startAction,
	}
	Cmd.Flags().String("acl", "acl.json", "file path for authentication")
	Cmd.Flags().StringP("listen", "l", "0.0.0.0:9986", "http server listen address")
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
