package pf

import (
	"time"

	"github.com/spf13/cobra"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:   "pf",
		Short: "Port-forwarding daemon act as ToH client",
		Args:  cobra.NoArgs,
		RunE:  startAction,
	}
	Cmd.Flags().StringP("server", "s", "", "the ToH server address")
	Cmd.Flags().StringP("api-key", "k", "", "the ToH api-key for authcate")
	Cmd.Flags().String("keepalive", "0s", "http/ws conn keepalive. 0s use system default")
	Cmd.Flags().Int64("udp-buf", 1472, "the maximum UDP packet size")
	Cmd.Flags().StringSliceP("forward", "f", []string{}, "tunnel mapping (i.e. udp/0.0.0.0:53/8.8.8.8:53)")

	Cmd.MarkFlagRequired("server")
	Cmd.MarkFlagRequired("api-key")
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
	if err != nil {
		return
	}
	options.UDPBuf, err = cmd.Flags().GetInt64("udp-buf")
	if err != nil {
		return
	}
	keepalive, err := cmd.Flags().GetString("keepalive")
	if err != nil {
		return
	}
	options.Keepalive, err = time.ParseDuration(keepalive)
	return
}
