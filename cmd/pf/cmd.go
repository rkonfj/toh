package pf

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:     "pf",
		Short:   "Client for port-forwarding",
		Args:    cobra.NoArgs,
		PreRunE: initAction,
		RunE:    startAction,
	}
	Cmd.Flags().StringP("server", "s", "", "the ToH server address")
	Cmd.Flags().StringP("api-key", "k", "", "the ToH api-key for authcate")
	Cmd.Flags().StringSliceP("forward", "f", []string{}, "tunnel mapping (<net>/<local>/<remote>, ie: udp/0.0.0.0:53/8.8.8.8:53)")

	Cmd.MarkFlagRequired("server")
	Cmd.MarkFlagRequired("api-key")
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
	options, err := processOptions(cmd)
	if err != nil {
		return err
	}

	tm, err := NewTunnelManager(options)
	if err != nil {
		return err
	}

	tm.Run()
	return nil
}

func processOptions(cmd *cobra.Command) (options Options, err error) {
	options.Forwards, err = cmd.Flags().GetStringSlice("forward")
	if err != nil {
		return
	}
	options.Server, err = cmd.Flags().GetString("server")
	if err != nil {
		return
	}
	options.ApiKey, err = cmd.Flags().GetString("api-key")
	return
}
