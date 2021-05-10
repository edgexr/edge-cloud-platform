package mccli

import (
	"fmt"
	"io"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

const mcctl = "mcctl"

func GetRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               mcctl,
		PersistentPreRunE: PreRunE,
		RunE:              cli.GroupRunE,
	}

	// User and Organizational Management
	managementCommands := []*cobra.Command{
		getLoginCmd(),
		getCmdGroup(ormctl.UserGroup),
		getCmdGroup(ormctl.RoleGroup),
		getCmdGroup(ormctl.OrgGroup),
		getCmdGroup(ormctl.BillingOrgGroup),
	}
	operatorCommands := []*cobra.Command{
		getCmdGroup(ormctl.CloudletGroup),
		getCmdGroup(ormctl.CloudletPoolGroup),
		getCmdGroup(ormctl.CloudletPoolInvitationGroup, ormctl.CloudletPoolAccessGroup),
		getCmdGroup(ormctl.CloudletInfoGroup),
		getCmdGroup(ormctl.TrustPolicyGroup),
		getCmdGroup(ormctl.ResTagTableGroup),
		getCmdGroup(ormctl.OperatorCodeGroup),
		getCmdGroup(ormctl.CloudletRefsGroup),
		getCmdGroup(ormctl.VMPoolGroup),
	}
	developerCommands := []*cobra.Command{
		getDevCloudletShowCommand(),
		getCmdGroup(ormctl.CloudletPoolResponseGroup, ormctl.CloudletPoolAccessGroup),
		getCmdGroup(ormctl.AppGroup),
		getCmdGroup(ormctl.ClusterInstGroup),
		getCmdGroup(ormctl.AppInstGroup),
		getCmdGroup(ormctl.AutoScalePolicyGroup),
		getCmdGroup(ormctl.AutoProvPolicyGroup),
		getCmdGroup(ormctl.AppInstClientGroup),
		getCmdGroup(ormctl.AppInstRefsGroup),
		getCmdGroup(ormctl.AppInstLatencyGroup),
		getExecCmd("RunCommandCli"),
		getExecCmd("RunConsole"),
		getExecCmd("ShowLogsCli"),
	}
	adminCommands := []*cobra.Command{
		getCmdGroup(ormctl.ControllerGroup),
		getCmdGroup(ormctl.ConfigGroup),
		getCmdGroup(ormctl.FlavorGroup),
		getCmdGroup(ormctl.NodeGroup),
		getCmdGroup(ormctl.SettingsGroup),
		getCmdGroup(ormctl.AlertGroup),
		getCmdGroup(ormctl.DebugGroup),
		getCmdGroup(ormctl.DeviceGroup),
		getCmdGroup(ormctl.ClusterRefsGroup),
		getCmdGroup(ormctl.RepositoryGroup),
		getExecCmd("AccessCloudletCli"),
		getCmdGroup(ormctl.SpansGroup),
		getCmd("RestrictedUpdateUser"),
		getCmd("RestrictedUpdateOrg"),
	}
	logsMetricsCommands := []*cobra.Command{
		getCmdGroup(ormctl.MetricsGroup),
		getCmdGroup(ormctl.BillingEventsGroup),
		getCmdGroup(ormctl.EventsGroup),
		getCmdGroup(ormctl.UsageGroup),
		getCmdGroup(ormctl.AlertReceiverGroup),
	}
	otherCommands := []*cobra.Command{
		GetVersionCmd(),
	}
	hiddenCommands := []*cobra.Command{
		getCmdGroup(ormctl.OrgCloudletGroup),     // for UI only
		getCmdGroup(ormctl.OrgCloudletInfoGroup), // for UI only
		getCmdGroup(ormctl.StreamObjGroup),       // for UI only
		getCmdGroup(ormctl.AuditGroup),           // deprecated
		getCmdGroup(ormctl.AllDataGroup),         // deprecated
	}

	rootCmd.AddCommand(managementCommands...)
	rootCmd.AddCommand(operatorCommands...)
	rootCmd.AddCommand(developerCommands...)
	rootCmd.AddCommand(adminCommands...)
	rootCmd.AddCommand(logsMetricsCommands...)
	rootCmd.AddCommand(otherCommands...)
	rootCmd.AddCommand(hiddenCommands...)

	isAdmin := false
	if _, err := os.Stat(GetAdminFile()); err == nil {
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

	rootCmd.PersistentFlags().StringVar(&Addr, "addr", "http://127.0.0.1:9900", "MC address")
	rootCmd.PersistentFlags().StringVar(&Token, "token", "", "JWT token")
	cli.AddInputFlags(rootCmd.PersistentFlags())
	cli.AddOutputFlags(rootCmd.PersistentFlags())
	cli.AddDebugFlag(rootCmd.PersistentFlags())
	rootCmd.PersistentFlags().BoolVar(&SkipVerify, "skipverify", false, "don't verify cert for TLS connections")

	cobra.EnableCommandSorting = false
	return rootCmd
}

func printCommandGroup(out io.Writer, desc string, pad int, cmds []*cobra.Command) {
	fmt.Fprintf(out, "\n%s\n", desc)
	for _, c := range cmds {
		fmt.Fprintf(out, "  %-*s%s\n", pad, c.Use, c.Short)
	}
}
