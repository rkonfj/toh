package main

import (
	"fmt"

	"github.com/rkonfj/toh/cmd/pf"
	"github.com/rkonfj/toh/cmd/s5"
	"github.com/rkonfj/toh/cmd/serve"
	"github.com/spf13/cobra"
)

var (
	Version, Commit string
)

func main() {
	cmd := &cobra.Command{
		Use:     "toh",
		Version: fmt.Sprintf("%s, commit %s", Version, Commit),
		Short:   "A tcp over http/ws toolset",
	}

	cmd.AddCommand(pf.Cmd)
	cmd.AddCommand(serve.Cmd)
	cmd.AddCommand(s5.Cmd)

	cmd.PersistentFlags().String("log-level", "info", "logrus logger level")

	cmd.Execute()
}
