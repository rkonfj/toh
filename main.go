package main

import (
	"fmt"
	"os"

	"github.com/rkonfj/toh/cmd/acl"
	"github.com/rkonfj/toh/cmd/pf"
	"github.com/rkonfj/toh/cmd/s5"
	"github.com/rkonfj/toh/cmd/serve"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:               "toh",
		Version:           fmt.Sprintf("%s, commit %s", spec.Version, spec.Commit),
		Short:             "A tcp/udp over http/websocket toolset",
		PersistentPreRunE: initAction,
	}

	cmd.AddCommand(pf.Cmd)
	cmd.AddCommand(serve.Cmd)
	cmd.AddCommand(s5.Cmd)
	cmd.AddCommand(acl.Cmd)

	cmd.PersistentFlags().String("log-level", "info", "logrus logger level")

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
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, DisableColors: true})
	return nil
}
