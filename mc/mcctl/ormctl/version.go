package ormctl

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/mobiledgex/edge-cloud/version"
	"github.com/spf13/cobra"
)

func GetVersionCmd() *cobra.Command {
	cmd := cli.Command{
		Use:   "version",
		Short: "Version of mcctl cli utility.",
	}
	cmd.Run = func(c *cli.Command, args []string) error {
		fmt.Printf("buildmaster: %s\n", version.BuildMaster)
		fmt.Printf("buildhead: %s\n", version.BuildHead)
		if version.BuildAuthor != "" {
			fmt.Printf("buildauthor: %s\n", version.BuildAuthor)
		}
		fmt.Printf("builddate: %s\n", version.BuildDate)
		return nil
	}
	return cmd.GenCmd()
}
