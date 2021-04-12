package main

import (
	"fmt"
	"io"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

const mcctl = "mcctl"

var rootCmd = &cobra.Command{
	Use:               mcctl,
	PersistentPreRunE: ormctl.PreRunE,
	RunE:              cli.GroupRunE,
}

func main() {
	// User and Organizational Management
	managementCommands := []*cobra.Command{
		ormctl.GetLoginCmd(),
		ormctl.GetUserCommand(),
		ormctl.GetRoleCommand(),
		ormctl.GetOrgCommand(),
		ormctl.GetBillingOrgCommand(),
	}
	operatorCommands := []*cobra.Command{
		ormctl.CloudletApiCmdsGroup,
		ormctl.CloudletPoolApiCmdsGroup,
		ormctl.GetCloudletPoolInvitationCommand(),
		ormctl.CloudletInfoApiCmdsGroup,
		ormctl.TrustPolicyApiCmdsGroup,
		ormctl.ResTagTableApiCmdsGroup,
		ormctl.OperatorCodeApiCmdsGroup,
		ormctl.CloudletRefsApiCmdsGroup,
		ormctl.VMPoolApiCmdsGroup,
	}
	devShowCloudlet := ormctl.ShowCloudletCmd.GenCmd()
	devShowCloudlet.Use = "cloudletshow"
	devShowCloudlet.Short = "View cloudlets"

	developerCommands := []*cobra.Command{
		devShowCloudlet,
		ormctl.GetCloudletPoolResponseCommand(),
		ormctl.AppApiCmdsGroup,
		ormctl.ClusterInstApiCmdsGroup,
		ormctl.AppInstApiCmdsGroup,
		ormctl.AutoScalePolicyApiCmdsGroup,
		ormctl.AutoProvPolicyApiCmdsGroup,
		ormctl.AppInstClientApiCmdsGroup,
		ormctl.AppInstRefsApiCmdsGroup,
		ormctl.AppInstLatencyApiCmdsGroup,
		ormctl.GetRunCommandCmd(),
		ormctl.GetRunConsoleCmd(),
		ormctl.GetShowLogsCmd(),
	}
	adminCommands := []*cobra.Command{
		ormctl.GetControllerCommand(),
		ormctl.GetConfigCommand(),
		ormctl.FlavorApiCmdsGroup,
		ormctl.NodeApiCmdsGroup,
		ormctl.SettingsApiCmdsGroup,
		ormctl.AlertApiCmdsGroup,
		ormctl.DebugApiCmdsGroup,
		ormctl.DeviceApiCmdsGroup,
		ormctl.ClusterRefsApiCmdsGroup,
		ormctl.GetAccessCloudletCmd(),
		ormctl.GetSpansCommand(),
		ormctl.GetRestrictedUserUpdateCmd(),
		ormctl.GetRestrictedOrgUpdateCmd(),
	}
	logsMetricsCommands := []*cobra.Command{
		ormctl.GetMetricsCommand(),
		ormctl.GetBillingEventsCommand(),
		ormctl.GetEventsCommand(),
		ormctl.GetUsageCommand(),
		ormctl.GetAlertReceiverCommand(),
	}
	otherCommands := []*cobra.Command{
		ormctl.GetVersionCmd(),
	}
	hiddenCommands := []*cobra.Command{
		ormctl.GetOrgCloudletCommand(),     // for UI only
		ormctl.GetOrgCloudletInfoCommand(), // for UI only
		ormctl.StreamObjApiCmdsGroup,       // for UI only
		ormctl.GetAuditCommand(),           // deprecated
		ormctl.GetAllDataCommand(),         // deprecated
	}

	rootCmd.AddCommand(managementCommands...)
	rootCmd.AddCommand(operatorCommands...)
	rootCmd.AddCommand(developerCommands...)
	rootCmd.AddCommand(adminCommands...)
	rootCmd.AddCommand(logsMetricsCommands...)
	rootCmd.AddCommand(otherCommands...)
	rootCmd.AddCommand(hiddenCommands...)

	isAdmin := false
	if _, err := os.Stat(ormctl.GetAdminFile()); err == nil {
		// This doesn't actually grant any admin privileges,
		// it just shows the commmands the help.
		isAdmin = true
	}

	rootCmdUsage := func(cmd *cobra.Command) error {
		out := cmd.OutOrStderr()
		fmt.Fprintf(out, "Usage: %s [command]\n", mcctl)

		pad := 0
		for _, c := range cmd.Commands() {
			if len(c.Use) > pad {
				pad = len(c.Use)
			}
		}
		pad += 2

		printCommandGroup(out, "User and Organization Commands", pad, managementCommands)
		printCommandGroup(out, "Operator Commands", pad, operatorCommands)
		printCommandGroup(out, "Developer Commands", pad, developerCommands)
		if isAdmin {
			printCommandGroup(out, "Admin-Only Commands", pad, adminCommands)
		}
		printCommandGroup(out, "Logs and Metrics Commands", pad, logsMetricsCommands)
		printCommandGroup(out, "Other Commands", pad, otherCommands)

		if cmd.HasAvailableLocalFlags() {
			fmt.Fprint(out, "\nFlags:\n", cli.LocalFlagsUsageNoNewline(cmd))
		}
		return nil
	}
	// Non-default usage funcs are inherited by all child commands,
	// but we don't want that in this case, so we need to be able to
	// use the default usage for child commands.
	defaultUsage := rootCmd.UsageFunc()
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		var err error
		if cmd.Use == mcctl {
			err = rootCmdUsage(cmd)
		} else {
			err = defaultUsage(cmd)
		}
		return err
	})

	rootCmd.PersistentFlags().StringVar(&ormctl.Addr, "addr", "http://127.0.0.1:9900", "MC address")
	rootCmd.PersistentFlags().StringVar(&ormctl.Token, "token", "", "JWT token")
	cli.AddInputFlags(rootCmd.PersistentFlags())
	cli.AddOutputFlags(rootCmd.PersistentFlags())
	cli.AddDebugFlag(rootCmd.PersistentFlags())
	rootCmd.PersistentFlags().BoolVar(&ormctl.SkipVerify, "skipverify", false, "don't verify cert for TLS connections")

	cobra.EnableCommandSorting = false
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func printCommandGroup(out io.Writer, desc string, pad int, cmds []*cobra.Command) {
	fmt.Fprintf(out, "\n%s\n", desc)
	for _, c := range cmds {
		fmt.Fprintf(out, "  %-*s%s\n", pad, c.Use, c.Short)
	}
}
