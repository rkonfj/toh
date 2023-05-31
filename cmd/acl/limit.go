package acl

import (
	"encoding/json"
	"os"

	"github.com/rkonfj/toh/server/api"
	"github.com/spf13/cobra"
)

type LimitOptions struct {
	Key      string
	Reset    bool
	Bytes    string
	InBytes  string
	OutBytes string
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
	return
}
