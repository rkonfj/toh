package acl

import (
	"encoding/json"
	"os"

	"github.com/rkonfj/toh/server/api"
	"github.com/spf13/cobra"
)

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
