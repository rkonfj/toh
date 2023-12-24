package serve

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/dustin/go-humanize"
	"github.com/rkonfj/toh/server"
	"github.com/spf13/cobra"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:   "serve",
		Short: "ToH server daemon",
		Args:  cobra.NoArgs,
		RunE:  runAction,
	}
	Cmd.Flags().String("acl", "acl.json", "file containing access control rules")
	Cmd.Flags().String("admin-key", "", "key to access the admin api (leave blank to disable admin api)")
	Cmd.Flags().String("copy-buf", "32ki", "buffer size for copying network data")
	Cmd.Flags().Bool("debug-mode", false, "run in debug mode (for developers)")
	Cmd.Flags().StringP("listen", "l", "127.0.0.1:9986", "http server listen address")
}

func runAction(cmd *cobra.Command, args []string) error {
	options, err := processServerOptions(cmd)
	if err != nil {
		return err
	}
	s, err := server.NewTohServer(options)
	if err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		s.Shutdown(context.Background())
	}()
	s.Run()
	return nil
}

func processServerOptions(cmd *cobra.Command) (options server.Options, err error) {
	options.Listen, err = cmd.Flags().GetString("listen")
	if err != nil {
		return
	}
	options.ACL, err = cmd.Flags().GetString("acl")
	if err != nil {
		return
	}
	options.AdminKey, err = cmd.Flags().GetString("admin-key")
	if err != nil {
		return
	}
	options.DebugMode, err = cmd.Flags().GetBool("debug-mode")
	if err != nil {
		return
	}
	copyBuf, err := cmd.Flags().GetString("copy-buf")
	if err != nil {
		return
	}
	options.Buf, err = humanize.ParseBytes(copyBuf)
	return
}
