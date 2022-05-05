// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mccli

import (
	"fmt"
	"io"
	"os"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-infra/mc/ormclient"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/spf13/cobra"
)

const mcctl = "mcctl"

type RootCommand struct {
	addr       string
	token      string
	skipVerify bool
	client     ormclient.Client
	CobraCmd   *cobra.Command
	clearState bool
}

// Clear any state if RootCommand is being used for multiple calls
// (happens only when reused for unit-tests.
func (s *RootCommand) ClearState() {
	s.addr = ""
	s.token = ""
	s.skipVerify = false
	s.clearState = true
}

func GetRootCommand() *RootCommand {
	rc := &RootCommand{}
	rootCmd := &cobra.Command{
		Use:               mcctl,
		PersistentPreRunE: rc.PreRunE,
		RunE:              cli.GroupRunE,
	}
	rc.CobraCmd = rootCmd

	// User and Organizational Management
	managementCommands := []*cobra.Command{
		rc.getLoginCmd(),
		rc.getCmdGroup(ormctl.UserGroup),
		rc.getCmdGroup(ormctl.RoleGroup),
		rc.getCmdGroup(ormctl.OrgGroup),
		rc.getCmdGroup(ormctl.BillingOrgGroup),
	}
	operatorCommands := []*cobra.Command{
		rc.getCmdGroup(ormctl.CloudletGroup),
		rc.getCmdGroup(ormctl.CloudletPoolGroup),
		rc.getCmdGroup(ormctl.CloudletPoolInvitationGroup, ormctl.CloudletPoolAccessGroup),
		rc.getCmdGroup(ormctl.CloudletInfoGroup),
		rc.getCmdGroup(ormctl.TrustPolicyGroup),
		rc.getCmdGroup(ormctl.ResTagTableGroup),
		rc.getCmdGroup(ormctl.OperatorCodeGroup),
		rc.getCmdGroup(ormctl.CloudletRefsGroup),
		rc.getCmdGroup(ormctl.VMPoolGroup),
		rc.getCmdGroup(ormctl.ReporterGroup),
		rc.getCmdGroup(ormctl.GPUDriverGroup),
		rc.getCmdGroup(ormctl.TrustPolicyExceptionGroup),
		rc.getCmdGroup(ormctl.NetworkGroup),
		rc.getReportCmdGroup(),
		rc.getCmdGroup(ormctl.FederatorGroup),
		rc.getCmdGroup(ormctl.FederatorZoneGroup),
		rc.getCmdGroup(ormctl.FederationGroup),
	}
	developerCommands := []*cobra.Command{
		rc.getDevCloudletShowCommand(),
		rc.getCmdGroup(ormctl.CloudletPoolResponseGroup, ormctl.CloudletPoolAccessGroup),
		rc.getCmdGroup(ormctl.AppGroup),
		rc.getCmdGroup(ormctl.ClusterInstGroup),
		rc.getCmdGroup(ormctl.AppInstGroup),
		rc.getCmdGroup(ormctl.AutoScalePolicyGroup),
		rc.getCmdGroup(ormctl.AutoProvPolicyGroup),
		rc.getCmdGroup(ormctl.AppInstClientGroup),
		rc.getCmdGroup(ormctl.AppInstRefsGroup),
		rc.getCmdGroup(ormctl.AppInstLatencyGroup),
		rc.getCmdGroup(ormctl.TrustPolicyExceptionGroup),
		rc.getExecCmd("RunCommandCli", cli.AddTtyFlags),
		rc.getExecCmd("RunConsole", cli.NoFlags),
		rc.getExecCmd("ShowLogsCli", cli.NoFlags),
	}
	adminCommands := []*cobra.Command{
		rc.getCmdGroup(ormctl.ControllerGroup),
		rc.getCmdGroup(ormctl.ConfigGroup),
		rc.getCmdGroup(ormctl.FlavorGroup),
		rc.getCmdGroup(ormctl.NodeGroup),
		rc.getCmdGroup(ormctl.SettingsGroup),
		rc.getCmdGroup(ormctl.AlertGroup),
		rc.getCmdGroup(ormctl.DebugGroup),
		rc.getCmdGroup(ormctl.DeviceGroup),
		rc.getCmdGroup(ormctl.ClusterRefsGroup),
		rc.getCmdGroup(ormctl.RepositoryGroup),
		rc.getExecCmd("AccessCloudletCli", cli.AddTtyFlags),
		rc.getCmdGroup(ormctl.SpansGroup),
		rc.getCmd("RestrictedUpdateUser"),
		rc.getCmd("RestrictedUpdateOrg"),
		rc.getCmdGroup(ormctl.RateLimitSettingsGroup),
		rc.getCmdGroup(ormctl.RateLimitSettingsMcGroup),
	}
	logsMetricsCommands := []*cobra.Command{
		rc.getCmdGroup(ormctl.MetricsGroup),
		rc.getCmdGroup(ormctl.BillingEventsGroup),
		rc.getCmdGroup(ormctl.EventsGroup),
		rc.getCmdGroup(ormctl.UsageGroup),
		rc.getCmdGroup(ormctl.AlertReceiverGroup),
		rc.getCmdGroup(ormctl.AlertPolicyGroup),
	}
	otherCommands := []*cobra.Command{
		GetVersionCmd(),
	}
	hiddenCommands := []*cobra.Command{
		rc.getCmdGroup(ormctl.OrgCloudletGroup),     // for UI only
		rc.getCmdGroup(ormctl.OrgCloudletInfoGroup), // for UI only
		rc.getCmdGroup(ormctl.StreamObjGroup),       // for UI only
		rc.getCmdGroup(ormctl.ReportDataGroup),      // for testingonly
		rc.getCmdGroup(ormctl.MetricsV2Group),       // api is hidden for now
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

	rootCmd.PersistentFlags().StringVar(&rc.addr, "addr", "http://127.0.0.1:9900", "MC address")
	rootCmd.PersistentFlags().StringVar(&rc.token, "token", "", "JWT token")
	cli.AddInputFlags(rootCmd.PersistentFlags())
	cli.AddOutputFlags(rootCmd.PersistentFlags())
	cli.AddDebugFlag(rootCmd.PersistentFlags())
	rootCmd.PersistentFlags().BoolVar(&rc.skipVerify, "skipverify", false, "don't verify cert for TLS connections")

	cobra.EnableCommandSorting = false
	return rc
}

func printCommandGroup(out io.Writer, desc string, pad int, cmds []*cobra.Command) {
	fmt.Fprintf(out, "\n%s\n", desc)
	for _, c := range cmds {
		fmt.Fprintf(out, "  %-*s%s\n", pad, c.Use, c.Short)
	}
}

// For unit-testing, force default transport to allow http requests to be mocked
func (s *RootCommand) ForceDefaultTransport(enable bool) {
	s.client.ForceDefaultTransport = enable
}

func (s *RootCommand) EnablePrintTransformations() {
	s.client.EnablePrintTransformations()
}
