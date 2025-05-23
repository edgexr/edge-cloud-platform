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

package main

import (
	"fmt"
	"os"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/gencmd"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var addr string
var tlsCertFile string
var conn *grpc.ClientConn

var rootCmd = &cobra.Command{
	Use:                "edgectl",
	PersistentPreRunE:  connect,
	PersistentPostRunE: close,
}
var controllerCmd = &cobra.Command{
	Use: "controller",
}
var dmeCmd = &cobra.Command{
	Use: "dme",
}
var crmCmd = &cobra.Command{
	Use: "crm",
}

var completionCmd = &cobra.Command{
	Use:   "completion-script",
	Short: "Generates bash completion script",
	RunE: func(cmd *cobra.Command, args []string) error {
		filename := "edgectl-completion.bash"
		outfile, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("Unable to open file %s in current dir for write: %s", filename, err.Error())
		}
		rootCmd.GenBashCompletion(outfile)
		fmt.Printf("Wrote file %s in current dir. Move it to /usr/local/etc/bash_completion.d/ (OSX) or /etc/bash_completion.d/ (linux)\n", filename)
		fmt.Println("On OSX, make sure bash completion is installed:")
		fmt.Println("  brew install bash-completion")
		outfile.Close()
		return nil
	},
}

func connect(cmd *cobra.Command, args []string) error {
	var err error

	tlsMode := tls.NoTLS
	if tlsCertFile != "" {
		tlsMode = tls.MutualAuthTLS
	}
	dialOption, err := tls.GetTLSClientDialOption(tlsMode, addr, nil, tlsCertFile, false)
	if err != nil {
		return fmt.Errorf("Unable to get dial option for server: %s. error is: %s", addr, err.Error())
	}
	if dialOption == nil {
		return fmt.Errorf("Nil dial option for server: %s.", addr)
	}
	conn, err = grpc.Dial(addr, dialOption, grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})))
	if err != nil {
		return fmt.Errorf("Connect to server %s failed: %s", addr, err.Error())
	}
	gencmd.AppApiCmd = edgeproto.NewAppApiClient(conn)
	gencmd.OperatorCodeApiCmd = edgeproto.NewOperatorCodeApiClient(conn)
	gencmd.FlavorApiCmd = edgeproto.NewFlavorApiClient(conn)
	gencmd.AutoScalePolicyApiCmd = edgeproto.NewAutoScalePolicyApiClient(conn)
	gencmd.AutoProvPolicyApiCmd = edgeproto.NewAutoProvPolicyApiClient(conn)
	gencmd.TrustPolicyApiCmd = edgeproto.NewTrustPolicyApiClient(conn)
	gencmd.TrustPolicyExceptionApiCmd = edgeproto.NewTrustPolicyExceptionApiClient(conn)
	gencmd.ClusterInstApiCmd = edgeproto.NewClusterInstApiClient(conn)
	gencmd.CloudletApiCmd = edgeproto.NewCloudletApiClient(conn)
	gencmd.VMPoolApiCmd = edgeproto.NewVMPoolApiClient(conn)
	gencmd.AppInstApiCmd = edgeproto.NewAppInstApiClient(conn)
	gencmd.CloudletInfoApiCmd = edgeproto.NewCloudletInfoApiClient(conn)
	gencmd.AppInstInfoApiCmd = edgeproto.NewAppInstInfoApiClient(conn)
	gencmd.ClusterInstInfoApiCmd = edgeproto.NewClusterInstInfoApiClient(conn)
	gencmd.MatchEngineApiCmd = dme.NewMatchEngineApiClient(conn)
	gencmd.DebugApiCmd = edgeproto.NewDebugApiClient(conn)
	gencmd.ControllerApiCmd = edgeproto.NewControllerApiClient(conn)
	gencmd.SvcNodeApiCmd = edgeproto.NewSvcNodeApiClient(conn)
	gencmd.ZonePoolApiCmd = edgeproto.NewZonePoolApiClient(conn)
	gencmd.AlertApiCmd = edgeproto.NewAlertApiClient(conn)
	gencmd.ResTagTableApiCmd = edgeproto.NewResTagTableApiClient(conn)
	gencmd.SettingsApiCmd = edgeproto.NewSettingsApiClient(conn)
	execApiCmd = edgeproto.NewExecApiClient(conn)
	gencmd.AppInstClientApiCmd = edgeproto.NewAppInstClientApiClient(conn)
	gencmd.DeviceApiCmd = edgeproto.NewDeviceApiClient(conn)
	gencmd.OrganizationApiCmd = edgeproto.NewOrganizationApiClient(conn)
	gencmd.CloudletRefsApiCmd = edgeproto.NewCloudletRefsApiClient(conn)
	gencmd.ClusterRefsApiCmd = edgeproto.NewClusterRefsApiClient(conn)
	gencmd.AppInstRefsApiCmd = edgeproto.NewAppInstRefsApiClient(conn)
	gencmd.StreamObjApiCmd = edgeproto.NewStreamObjApiClient(conn)
	gencmd.AppInstLatencyApiCmd = edgeproto.NewAppInstLatencyApiClient(conn)
	gencmd.GPUDriverApiCmd = edgeproto.NewGPUDriverApiClient(conn)
	gencmd.AlertPolicyApiCmd = edgeproto.NewAlertPolicyApiClient(conn)
	gencmd.RateLimitSettingsApiCmd = edgeproto.NewRateLimitSettingsApiClient(conn)
	gencmd.NetworkApiCmd = edgeproto.NewNetworkApiClient(conn)
	return nil
}

func close(cmd *cobra.Command, args []string) error {
	conn.Close()
	return nil
}

func main() {
	cobra.EnableCommandSorting = false

	rootCmd.AddCommand(controllerCmd)
	rootCmd.AddCommand(dmeCmd)
	rootCmd.AddCommand(crmCmd)
	rootCmd.AddCommand(completionCmd)
	rootCmd.PersistentFlags().StringVar(&addr, "addr", "127.0.0.1:55001", "address to connect to")
	rootCmd.PersistentFlags().StringVar(&tlsCertFile, "tls", "", "tls cert file")
	cli.AddInputFlags(rootCmd.PersistentFlags())
	cli.AddOutputFlags(rootCmd.PersistentFlags())
	cli.AddDebugFlag(rootCmd.PersistentFlags())
	cli.AddHideTagsFormatFlag(rootCmd.PersistentFlags())

	controllerCmd.AddCommand(gencmd.AppApiCmds...)
	controllerCmd.AddCommand(gencmd.OperatorCodeApiCmds...)
	controllerCmd.AddCommand(gencmd.FlavorApiCmds...)
	controllerCmd.AddCommand(gencmd.AutoScalePolicyApiCmds...)
	controllerCmd.AddCommand(gencmd.AutoProvPolicyApiCmds...)
	controllerCmd.AddCommand(gencmd.TrustPolicyApiCmds...)
	controllerCmd.AddCommand(gencmd.TrustPolicyExceptionApiCmds...)
	controllerCmd.AddCommand(gencmd.NetworkApiCmds...)
	controllerCmd.AddCommand(gencmd.ClusterInstApiCmds...)
	controllerCmd.AddCommand(gencmd.CloudletApiCmds...)
	controllerCmd.AddCommand(gencmd.VMPoolApiCmds...)
	controllerCmd.AddCommand(gencmd.AppInstApiCmds...)
	controllerCmd.AddCommand(gencmd.DebugApiCmds...)
	controllerCmd.AddCommand(gencmd.CloudletInfoApiCmds...)
	controllerCmd.AddCommand(gencmd.ControllerApiCmds...)
	controllerCmd.AddCommand(gencmd.SvcNodeApiCmds...)
	controllerCmd.AddCommand(gencmd.ZonePoolApiCmds...)
	controllerCmd.AddCommand(gencmd.AlertApiCmds...)
	controllerCmd.AddCommand(gencmd.ResTagTableApiCmds...)
	controllerCmd.AddCommand(gencmd.SettingsApiCmds...)
	controllerCmd.AddCommand(gencmd.AppInstClientApiCmds...)
	controllerCmd.AddCommand(gencmd.DeviceApiCmds...)
	controllerCmd.AddCommand(gencmd.OrganizationApiCmds...)
	controllerCmd.AddCommand(gencmd.CloudletRefsApiCmds...)
	controllerCmd.AddCommand(gencmd.ClusterRefsApiCmds...)
	controllerCmd.AddCommand(gencmd.AppInstRefsApiCmds...)
	controllerCmd.AddCommand(gencmd.StreamObjApiCmds...)
	controllerCmd.AddCommand(gencmd.AppInstLatencyApiCmds...)
	controllerCmd.AddCommand(gencmd.GPUDriverApiCmds...)
	controllerCmd.AddCommand(gencmd.AlertPolicyApiCmds...)
	controllerCmd.AddCommand(gencmd.RateLimitSettingsApiCmds...)
	controllerCmd.AddCommand(createCmd.GenCmd())
	controllerCmd.AddCommand(deleteCmd.GenCmd())
	gencmd.RunCommandCmd.Run = runRunCommand
	gencmd.RunCommandCmd.AddFlagsFunc = cli.AddTtyFlags
	gencmd.ShowLogsCmd.Run = runShowLogs
	gencmd.RunConsoleCmd.Run = runRunConsole
	gencmd.AccessCloudletCmd.Run = runAccessCloudlet
	gencmd.AccessCloudletCmd.AddFlagsFunc = cli.AddTtyFlags
	controllerCmd.AddCommand(gencmd.RunCommandCmd.GenCmd(), gencmd.RunConsoleCmd.GenCmd(), gencmd.ShowLogsCmd.GenCmd(), gencmd.AccessCloudletCmd.GenCmd())

	dmeCmd.AddCommand(gencmd.MatchEngineApiCmds...)
	dmeCmd.AddCommand(gencmd.DebugApiCmds...)

	crmCmd.AddCommand(gencmd.DebugApiCmds...)
	crmCmd.AddCommand(gencmd.ClusterInstInfoApiCmds...)
	crmCmd.AddCommand(gencmd.AppInstInfoApiCmds...)

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
