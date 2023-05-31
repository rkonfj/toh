package acl

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

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
	fmt.Println("ok")
	return nil
}

func aclShow(cmd *cobra.Command, args []string) (err error) {
	keys, err := cli.ACLShow()
	if err != nil {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")
	err = enc.Encode(keys)
	return
}
