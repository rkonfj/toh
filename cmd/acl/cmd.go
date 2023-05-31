package acl

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/rkonfj/toh/server/api"
	"github.com/spf13/cobra"
)

var (
	Cmd *cobra.Command
	cli *api.ServerAdminClient
)

func init() {
	Cmd = &cobra.Command{
		Use:               "acl",
		Short:             "ToH server admin tool for acl",
		Args:              cobra.NoArgs,
		PersistentPreRunE: initAction,
	}

	cmdNew := &cobra.Command{
		Use:   "new",
		Short: "create an acl key",
		Args:  cobra.NoArgs,
		RunE:  aclNew,
	}
	cmdNew.Flags().String("name", "", "the acl key name (default not set)")

	cmdDel := &cobra.Command{
		Use:   "del",
		Short: "delete the acl key",
		Args:  cobra.NoArgs,
		RunE:  aclDel,
	}
	cmdDel.Flags().String("key", "", "the acl key")
	cmdDel.MarkFlagRequired("key")

	cmdLimit := &cobra.Command{
		Use:   "limit",
		Short: "limit the acl key or get it's limit",
		Args:  cobra.NoArgs,
		RunE:  aclLimit,
	}
	cmdLimit.Flags().String("key", "", "the acl key")
	cmdLimit.Flags().Bool("reset", false, "reset acl key limit (default false)")
	cmdLimit.Flags().String("bytes", "", "the acl limit bytes (default not update)")
	cmdLimit.Flags().String("in-bytes", "", "the acl limit in bytes (default not update)")
	cmdLimit.Flags().String("out-bytes", "", "the acl limit out bytes (default not update)")
	cmdLimit.MarkFlagRequired("key")

	cmdUsage := &cobra.Command{
		Use:   "usage",
		Short: "reset the acl key usage or get it",
		Args:  cobra.NoArgs,
		RunE:  aclUsage,
	}
	cmdUsage.Flags().String("key", "", "the acl key")
	cmdUsage.Flags().Bool("reset", false, "reset acl key usage")
	cmdUsage.MarkFlagRequired("key")

	cmdShowACL := &cobra.Command{
		Use:   "show",
		Short: "show acl keys",
		Args:  cobra.NoArgs,
		RunE:  aclShow,
	}

	cmdWhitelistAdd := &cobra.Command{
		Use:   "add",
		Short: "add item to acl whitelist",
		Args:  cobra.ExactArgs(1),
		RunE:  addWhitelist,
	}

	cmdWhitelistDel := &cobra.Command{
		Use:   "del",
		Short: "delete item from acl whitelist",
		Args:  cobra.ExactArgs(1),
		RunE:  delWhitelist,
	}

	cmdWhitelistReset := &cobra.Command{
		Use:   "reset",
		Short: "reset acl whitelist",
		RunE:  resetWhitelist,
	}

	cmdWhitelist := &cobra.Command{
		Use:   "whitelist",
		Short: "manage the acl whitelist (what is allowed)",
	}
	cmdWhitelist.PersistentFlags().String("key", "", "the acl key")
	cmdWhitelist.MarkPersistentFlagRequired("key")

	cmdWhitelist.AddCommand(cmdWhitelistAdd)
	cmdWhitelist.AddCommand(cmdWhitelistDel)
	cmdWhitelist.AddCommand(cmdWhitelistReset)

	cmdBlacklistAdd := &cobra.Command{
		Use:   "add",
		Short: "add item to acl blacklist",
		Args:  cobra.MinimumNArgs(1),
		RunE:  addBlacklist,
	}

	cmdBlacklistDel := &cobra.Command{
		Use:   "del",
		Short: "delete item from acl blacklist",
		Args:  cobra.MinimumNArgs(1),
		RunE:  delBlacklist,
	}

	cmdBlacklist := &cobra.Command{
		Use:   "blacklist",
		Short: "manage the acl blacklist (what is forbidden)",
	}
	cmdBlacklistReset := &cobra.Command{
		Use:   "reset",
		Short: "reset acl blacklist",
		RunE:  resetBlacklist,
	}
	cmdBlacklist.PersistentFlags().String("key", "", "the acl key")
	cmdBlacklist.MarkPersistentFlagRequired("key")
	cmdBlacklist.AddCommand(cmdBlacklistAdd)
	cmdBlacklist.AddCommand(cmdBlacklistDel)
	cmdBlacklist.AddCommand(cmdBlacklistReset)

	Cmd.PersistentFlags().StringP("server", "s", "http://127.0.0.1:9986", "toh server")
	Cmd.PersistentFlags().StringP("admin-key", "k", "", "toh server admin key (default read from admin-key file)")
	Cmd.AddCommand(cmdNew)
	Cmd.AddCommand(cmdDel)
	Cmd.AddCommand(cmdLimit)
	Cmd.AddCommand(cmdUsage)
	Cmd.AddCommand(cmdShowACL)
	Cmd.AddCommand(cmdWhitelist)
	Cmd.AddCommand(cmdBlacklist)
}

func initAction(cmd *cobra.Command, args []string) (err error) {
	server, err := cmd.Flags().GetString("server")
	if err != nil {
		return err
	}

	adminKey, err := cmd.Flags().GetString("admin-key")
	if err != nil {
		return err
	}
	if len(adminKey) == 0 {
		adminKeyFile, err := os.Open(filepath.Join(os.TempDir(), "toh-admin-key"))
		if err == nil {
			defer adminKeyFile.Close()
			b, err := io.ReadAll(adminKeyFile)
			if err != nil {
				return err
			}
			adminKey = string(b)
		}
	}

	if len(server) == 0 {
		return errors.New("required flag `server` not set")
	}
	if len(adminKey) == 0 {
		return errors.New("required flag `admin-key` not set")
	}

	cli = api.NewServerAdminClient(server, adminKey)
	return nil
}
