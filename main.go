package main

import (
	"github.com/rkonfj/toh/cmd/pf"
	"github.com/rkonfj/toh/cmd/serve"
	socks5_cmd "github.com/rkonfj/toh/cmd/socks5"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "toh",
		Short: "A tcp over http/ws toolset",
	}

	cmd.AddCommand(pf.Cmd)
	cmd.AddCommand(serve.Cmd)
	cmd.AddCommand(socks5_cmd.Cmd)

	cmd.PersistentFlags().String("log-level", "info", "logrus logger level")

	cmd.Execute()
}
