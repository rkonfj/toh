package acl

import (
	"encoding/json"
	"os"
	"slices"

	"github.com/spf13/cobra"
)

func addWhitelist(cmd *cobra.Command, args []string) error {
	return updateWhitelist(cmd, func(old []string) []string {
		for _, a := range args {
			if slices.Contains(old, a) {
				continue
			}
			old = append(old, a)
		}
		return old
	})
}

func delWhitelist(cmd *cobra.Command, args []string) error {
	return updateWhitelist(cmd, func(old []string) []string {
		var newList []string
		for _, a := range old {
			if slices.Contains(args, a) {
				newList = append(newList, a)
			}
		}
		return newList
	})
}

func resetWhitelist(cmd *cobra.Command, args []string) error {
	return updateWhitelist(cmd, func(old []string) []string {
		return args
	})
}

func addBlacklist(cmd *cobra.Command, args []string) error {
	return updateBlacklist(cmd, func(old []string) []string {
		for _, a := range args {
			if slices.Contains(old, a) {
				continue
			}
			old = append(old, a)
		}
		return old
	})
}

func delBlacklist(cmd *cobra.Command, args []string) error {
	return updateBlacklist(cmd, func(old []string) []string {
		var newList []string
		for _, a := range old {
			if slices.Contains(args, a) {
				newList = append(newList, a)
			}
		}
		return newList
	})
}

func resetBlacklist(cmd *cobra.Command, args []string) error {
	return updateBlacklist(cmd, func(old []string) []string {
		return args
	})
}

func updateWhitelist(cmd *cobra.Command, update func(old []string) []string) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return err
	}
	l, err := cli.ACLGetLimit(key)
	if err != nil {
		return err
	}
	l.Whitelist = update(l.Whitelist)
	err = cli.ACLPatchLimit(key, l)
	if err == nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		err = enc.Encode(l.Whitelist)
	}
	return err
}

func updateBlacklist(cmd *cobra.Command, update func(old []string) []string) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return err
	}
	l, err := cli.ACLGetLimit(key)
	if err != nil {
		return err
	}
	l.Blacklist = update(l.Blacklist)
	err = cli.ACLPatchLimit(key, l)
	if err == nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		err = enc.Encode(l.Blacklist)
	}
	return err
}
