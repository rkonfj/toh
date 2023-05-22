package acl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

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
		Short:             "ToH server acl admin tool",
		Args:              cobra.NoArgs,
		PersistentPreRunE: initAction,
	}

	cmdNew := &cobra.Command{
		Use:   "new",
		Short: "new acl key",
		Args:  cobra.NoArgs,
		RunE:  aclNew,
	}
	cmdNew.Flags().String("name", "", "the acl key name")

	cmdDel := &cobra.Command{
		Use:   "del",
		Short: "del acl key",
		Args:  cobra.NoArgs,
		RunE:  aclDel,
	}
	cmdDel.Flags().String("key", "", "the acl key")
	cmdDel.MarkFlagRequired("key")

	cmdLimit := &cobra.Command{
		Use:   "limit",
		Short: "limit acl key",
		Args:  cobra.NoArgs,
		RunE:  aclLimit,
	}
	cmdLimit.Flags().String("key", "", "the acl key")
	cmdLimit.Flags().Bool("reset", false, "reset acl key limit")
	cmdLimit.Flags().String("bytes", "", "the acl limit bytes")
	cmdLimit.Flags().String("in-bytes", "", "the acl limit in bytes")
	cmdLimit.Flags().String("out-bytes", "", "the acl limit out bytes")
	cmdLimit.Flags().StringSlice("whitelist", []string{}, "the acl limit whitelist")
	cmdLimit.Flags().StringSlice("blacklist", []string{}, "the acl limit blacklist")
	cmdLimit.MarkFlagRequired("key")

	cmdUsage := &cobra.Command{
		Use:   "usage",
		Short: "acl key usage",
		Args:  cobra.NoArgs,
		RunE:  aclUsage,
	}
	cmdUsage.Flags().String("key", "", "the acl key")
	cmdUsage.Flags().Bool("reset", false, "reset acl key usage")
	cmdUsage.MarkFlagRequired("key")

	Cmd.PersistentFlags().StringP("server", "s", "http://127.0.0.1:9986", "toh server")
	Cmd.PersistentFlags().StringP("admin-key", "k", "", "toh server admin-key")
	Cmd.AddCommand(cmdNew)
	Cmd.AddCommand(cmdDel)
	Cmd.AddCommand(cmdLimit)
	Cmd.AddCommand(cmdUsage)
}

func initAction(cmd *cobra.Command, args []string) (err error) {
	server := os.Getenv("TOH_SERVER")
	if len(server) == 0 {
		server, err = cmd.Flags().GetString("server")
		if err != nil {
			return err
		}
	}

	adminKey := os.Getenv("TOH_ADMIN_KEY")
	if len(adminKey) == 0 {
		adminKey, err = cmd.Flags().GetString("admin-key")
		if err != nil {
			return err
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

func aclNew(cmd *cobra.Command, args []string) error {
	name, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}
	key, err := cli.ACLNewKey(name)
	if err != nil {
		return err
	}
	fmt.Println(key)
	return nil
}

func aclDel(cmd *cobra.Command, args []string) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return err
	}
	err = cli.ACLDelKey(key)
	if err != nil {
		return err
	}
	return nil
}

type LimitOptions struct {
	Key       string
	Reset     bool
	Bytes     string
	InBytes   string
	OutBytes  string
	Witelist  []string
	Blacklist []string
}

func aclLimit(cmd *cobra.Command, args []string) (err error) {
	opts, err := processLimitOptions(cmd)
	if err != nil {
		return
	}
	if opts.Reset {
		err = cli.ACLPatchLimit(opts.Key, nil)
		if err != nil {
			return
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		err = enc.Encode(api.Limit{})
		return
	}
	l, err := cli.ACLGetLimit(opts.Key)
	if err != nil {
		return err
	}
	var update bool
	if len(opts.Bytes) != 0 {
		l.Bytes = opts.Bytes
		update = true
	}
	if len(opts.InBytes) != 0 {
		l.InBytes = opts.InBytes
		update = true
	}
	if len(opts.OutBytes) != 0 {
		l.OutBytes = opts.OutBytes
		update = true
	}
	if len(opts.Blacklist) != 0 {
		l.Blacklist = append(l.Blacklist, opts.Blacklist...)
		update = true
	}
	if len(opts.Witelist) != 0 {
		l.Whitelist = append(l.Whitelist, opts.Witelist...)
		update = true
	}
	if update {
		err = cli.ACLPatchLimit(opts.Key, l)
		if err != nil {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")
	err = enc.Encode(l)
	return
}

func aclUsage(cmd *cobra.Command, args []string) (err error) {
	reset, err := cmd.Flags().GetBool("reset")
	if err != nil {
		return
	}
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return
	}
	if reset {
		err = cli.ACLDelUsage(key)
		if err != nil {
			return
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		err = enc.Encode(api.BytesUsage{})
		return
	}
	usage, err := cli.ACLGetUsage(key)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")
	err = enc.Encode(usage)
	return
}

func processLimitOptions(cmd *cobra.Command) (options LimitOptions, err error) {
	options.Key, err = cmd.Flags().GetString("key")
	if err != nil {
		return
	}
	options.Reset, err = cmd.Flags().GetBool("reset")
	if err != nil {
		return
	}
	options.Bytes, err = cmd.Flags().GetString("bytes")
	if err != nil {
		return
	}
	options.InBytes, err = cmd.Flags().GetString("in-bytes")
	if err != nil {
		return
	}
	options.OutBytes, err = cmd.Flags().GetString("out-bytes")
	if err != nil {
		return
	}
	options.Witelist, err = cmd.Flags().GetStringSlice("whitelist")
	if err != nil {
		return
	}
	options.Blacklist, err = cmd.Flags().GetStringSlice("blacklist")
	return
}
