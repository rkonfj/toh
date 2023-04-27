package main

import (
	"fmt"
	"os"

	"github.com/rkonfj/toh/cmd/pf"
	"github.com/rkonfj/toh/cmd/s5"
	"github.com/rkonfj/toh/cmd/serve"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	Version, Commit string
)

func main() {
	cmd := &cobra.Command{
		Use:               "toh",
		Version:           fmt.Sprintf("%s, commit %s", Version, Commit),
		Short:             "A tcp over http/ws toolset",
		PersistentPreRunE: initAction,
	}

	cmd.AddCommand(pf.Cmd)
	cmd.AddCommand(serve.Cmd)
	cmd.AddCommand(s5.Cmd)

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
