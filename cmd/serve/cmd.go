package serve

import (
	"github.com/rkonfj/toh/server"
	"github.com/spf13/cobra"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:   "serve",
		Short: "ToH server daemon",
		Args:  cobra.NoArgs,
		RunE:  startAction,
	}
	Cmd.Flags().String("acl", "acl.json", "file path for authentication")
	Cmd.Flags().StringP("listen", "l", "localhost:9986", "http server listen address")
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
