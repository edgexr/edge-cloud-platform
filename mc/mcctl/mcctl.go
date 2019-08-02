package main

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:               "mcctl",
	PersistentPreRunE: ormctl.PreRunE,
}

func main() {
	rootCmd.AddCommand(ormctl.GetLoginCmd())
	rootCmd.AddCommand(ormctl.GetUserCommand())
	rootCmd.AddCommand(ormctl.GetRoleCommand())
	rootCmd.AddCommand(ormctl.GetOrgCommand())
	rootCmd.AddCommand(ormctl.GetControllerCommand())
	rootCmd.AddCommand(ormctl.GetAllDataCommand())
	regionCmds := ormctl.GetRegionCommand()
	regionCmds.AddCommand(ormctl.GetRunCommandCmd())
	rootCmd.AddCommand(regionCmds)
	rootCmd.AddCommand(ormctl.GetConfigCommand())
	rootCmd.AddCommand(ormctl.GetAuditCommand())

	rootCmd.PersistentFlags().StringVar(&ormctl.Addr, "addr", "http://127.0.0.1:9900", "MC address")
	rootCmd.PersistentFlags().StringVar(&ormctl.Token, "token", "", "JWT token")
	rootCmd.PersistentFlags().StringVar(&ormctl.Data, "data", "", "json formatted input data, alternative to name=val args list")
	rootCmd.PersistentFlags().StringVar(&ormctl.Datafile, "datafile", "", "file containing json/yaml formatted input data, alternative to name=val args list")
	rootCmd.PersistentFlags().StringVar(&ormctl.OutputFormat, "output-format", cmdsup.OutputFormatYaml, fmt.Sprintf("output format: %s, %s, or %s", cmdsup.OutputFormatYaml, cmdsup.OutputFormatJson, cmdsup.OutputFormatJsonCompact))
	rootCmd.PersistentFlags().BoolVar(&ormctl.Parsable, "parsable", false, "generate parsable output")
	rootCmd.PersistentFlags().BoolVar(&ormctl.SkipVerify, "skipverify", false, "don't verify cert for TLS connections")
	rootCmd.PersistentFlags().BoolVar(&ormctl.Debug, "debug", false, "debug")

	cobra.EnableCommandSorting = false
	rootCmd.SilenceUsage = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
