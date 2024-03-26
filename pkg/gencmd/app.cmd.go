// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

package gencmd

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	distributed_match_engine "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"io"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
func AppHideTags(in *edgeproto.App) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.AuthPublicKey = ""
	}
	for i0 := 0; i0 < len(in.Configs); i0++ {
	}
	if _, found := tags["nocmp"]; found {
		in.Revision = ""
	}
	if _, found := tags["timestamp"]; found {
		in.CreatedAt = distributed_match_engine.Timestamp{}
	}
	if _, found := tags["timestamp"]; found {
		in.UpdatedAt = distributed_match_engine.Timestamp{}
	}
	for i0 := 0; i0 < len(in.RequiredOutboundConnections); i0++ {
	}
}

func DeploymentCloudletRequestHideTags(in *edgeproto.DeploymentCloudletRequest) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.App.AuthPublicKey = ""
	}
	for i1 := 0; i1 < len(in.App.Configs); i1++ {
	}
	if _, found := tags["nocmp"]; found {
		in.App.Revision = ""
	}
	if _, found := tags["timestamp"]; found {
		in.App.CreatedAt = distributed_match_engine.Timestamp{}
	}
	if _, found := tags["timestamp"]; found {
		in.App.UpdatedAt = distributed_match_engine.Timestamp{}
	}
	for i1 := 0; i1 < len(in.App.RequiredOutboundConnections); i1++ {
	}
}

var AppApiCmd edgeproto.AppApiClient

var CreateAppCmd = &cli.Command{
	Use:          "CreateApp",
	RequiredArgs: strings.Join(CreateAppRequiredArgs, " "),
	OptionalArgs: strings.Join(CreateAppOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	SpecialArgs:  &AppSpecialArgs,
	Comments:     AppComments,
	ReqData:      &edgeproto.App{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateApp,
}

func runCreateApp(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.App)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateApp(c, obj)
}

func CreateApp(c *cli.Command, in *edgeproto.App) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.CreateApp(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateApp failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateApps(c *cli.Command, data []edgeproto.App, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateApp %v\n", data[ii])
		myerr := CreateApp(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteAppCmd = &cli.Command{
	Use:          "DeleteApp",
	RequiredArgs: strings.Join(DeleteAppRequiredArgs, " "),
	OptionalArgs: strings.Join(DeleteAppOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	SpecialArgs:  &AppSpecialArgs,
	Comments:     AppComments,
	ReqData:      &edgeproto.App{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteApp,
}

func runDeleteApp(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.App)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteApp(c, obj)
}

func DeleteApp(c *cli.Command, in *edgeproto.App) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.DeleteApp(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteApp failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteApps(c *cli.Command, data []edgeproto.App, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteApp %v\n", data[ii])
		myerr := DeleteApp(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateAppCmd = &cli.Command{
	Use:          "UpdateApp",
	RequiredArgs: strings.Join(AppRequiredArgs, " "),
	OptionalArgs: strings.Join(AppOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	SpecialArgs:  &AppSpecialArgs,
	Comments:     AppComments,
	ReqData:      &edgeproto.App{},
	ReplyData:    &edgeproto.Result{},
	Run:          runUpdateApp,
}

func runUpdateApp(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.App)
	jsonMap, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	obj.Fields = cli.GetSpecifiedFields(jsonMap, c.ReqData)
	return UpdateApp(c, obj)
}

func UpdateApp(c *cli.Command, in *edgeproto.App) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.UpdateApp(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateApp failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func UpdateApps(c *cli.Command, data []edgeproto.App, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateApp %v\n", data[ii])
		myerr := UpdateApp(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowAppCmd = &cli.Command{
	Use:          "ShowApp",
	OptionalArgs: strings.Join(append(AppRequiredArgs, AppOptionalArgs...), " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	SpecialArgs:  &AppSpecialArgs,
	Comments:     AppComments,
	ReqData:      &edgeproto.App{},
	ReplyData:    &edgeproto.App{},
	Run:          runShowApp,
}

func runShowApp(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.App)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowApp(c, obj)
}

func ShowApp(c *cli.Command, in *edgeproto.App) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppApiCmd.ShowApp(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowApp failed: %s", errstr)
	}

	objs := make([]*edgeproto.App, 0)
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			errstr := err.Error()
			st, ok := status.FromError(err)
			if ok {
				errstr = st.Message()
			}
			return fmt.Errorf("ShowApp recv failed: %s", errstr)
		}
		AppHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowApps(c *cli.Command, data []edgeproto.App, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowApp %v\n", data[ii])
		myerr := ShowApp(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AddAppAutoProvPolicyCmd = &cli.Command{
	Use:          "AddAppAutoProvPolicy",
	RequiredArgs: strings.Join(AppAutoProvPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AppAutoProvPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAutoProvPolicyAliasArgs, " "),
	SpecialArgs:  &AppAutoProvPolicySpecialArgs,
	Comments:     AppAutoProvPolicyComments,
	ReqData:      &edgeproto.AppAutoProvPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runAddAppAutoProvPolicy,
}

func runAddAppAutoProvPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AppAutoProvPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return AddAppAutoProvPolicy(c, obj)
}

func AddAppAutoProvPolicy(c *cli.Command, in *edgeproto.AppAutoProvPolicy) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.AddAppAutoProvPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("AddAppAutoProvPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func AddAppAutoProvPolicys(c *cli.Command, data []edgeproto.AppAutoProvPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("AddAppAutoProvPolicy %v\n", data[ii])
		myerr := AddAppAutoProvPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var RemoveAppAutoProvPolicyCmd = &cli.Command{
	Use:          "RemoveAppAutoProvPolicy",
	RequiredArgs: strings.Join(AppAutoProvPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AppAutoProvPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAutoProvPolicyAliasArgs, " "),
	SpecialArgs:  &AppAutoProvPolicySpecialArgs,
	Comments:     AppAutoProvPolicyComments,
	ReqData:      &edgeproto.AppAutoProvPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runRemoveAppAutoProvPolicy,
}

func runRemoveAppAutoProvPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AppAutoProvPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return RemoveAppAutoProvPolicy(c, obj)
}

func RemoveAppAutoProvPolicy(c *cli.Command, in *edgeproto.AppAutoProvPolicy) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.RemoveAppAutoProvPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("RemoveAppAutoProvPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func RemoveAppAutoProvPolicys(c *cli.Command, data []edgeproto.AppAutoProvPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("RemoveAppAutoProvPolicy %v\n", data[ii])
		myerr := RemoveAppAutoProvPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AddAppAlertPolicyCmd = &cli.Command{
	Use:          "AddAppAlertPolicy",
	RequiredArgs: strings.Join(AppAlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AppAlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAlertPolicyAliasArgs, " "),
	SpecialArgs:  &AppAlertPolicySpecialArgs,
	Comments:     AppAlertPolicyComments,
	ReqData:      &edgeproto.AppAlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runAddAppAlertPolicy,
}

func runAddAppAlertPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AppAlertPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return AddAppAlertPolicy(c, obj)
}

func AddAppAlertPolicy(c *cli.Command, in *edgeproto.AppAlertPolicy) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.AddAppAlertPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("AddAppAlertPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func AddAppAlertPolicys(c *cli.Command, data []edgeproto.AppAlertPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("AddAppAlertPolicy %v\n", data[ii])
		myerr := AddAppAlertPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var RemoveAppAlertPolicyCmd = &cli.Command{
	Use:          "RemoveAppAlertPolicy",
	RequiredArgs: strings.Join(AppAlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AppAlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAlertPolicyAliasArgs, " "),
	SpecialArgs:  &AppAlertPolicySpecialArgs,
	Comments:     AppAlertPolicyComments,
	ReqData:      &edgeproto.AppAlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runRemoveAppAlertPolicy,
}

func runRemoveAppAlertPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AppAlertPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return RemoveAppAlertPolicy(c, obj)
}

func RemoveAppAlertPolicy(c *cli.Command, in *edgeproto.AppAlertPolicy) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AppApiCmd.RemoveAppAlertPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("RemoveAppAlertPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func RemoveAppAlertPolicys(c *cli.Command, data []edgeproto.AppAlertPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("RemoveAppAlertPolicy %v\n", data[ii])
		myerr := RemoveAppAlertPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowCloudletsForAppDeploymentCmd = &cli.Command{
	Use:          "ShowCloudletsForAppDeployment",
	OptionalArgs: strings.Join(append(DeploymentCloudletRequestRequiredArgs, DeploymentCloudletRequestOptionalArgs...), " "),
	AliasArgs:    strings.Join(DeploymentCloudletRequestAliasArgs, " "),
	SpecialArgs:  &DeploymentCloudletRequestSpecialArgs,
	Comments:     DeploymentCloudletRequestComments,
	ReqData:      &edgeproto.DeploymentCloudletRequest{},
	ReplyData:    &edgeproto.CloudletKey{},
	Run:          runShowCloudletsForAppDeployment,
}

func runShowCloudletsForAppDeployment(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.DeploymentCloudletRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowCloudletsForAppDeployment(c, obj)
}

func ShowCloudletsForAppDeployment(c *cli.Command, in *edgeproto.DeploymentCloudletRequest) error {
	if AppApiCmd == nil {
		return fmt.Errorf("AppApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppApiCmd.ShowCloudletsForAppDeployment(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowCloudletsForAppDeployment failed: %s", errstr)
	}

	objs := make([]*edgeproto.CloudletKey, 0)
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			errstr := err.Error()
			st, ok := status.FromError(err)
			if ok {
				errstr = st.Message()
			}
			return fmt.Errorf("ShowCloudletsForAppDeployment recv failed: %s", errstr)
		}
		if cli.OutputStream {
			c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
			continue
		}
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowCloudletsForAppDeployments(c *cli.Command, data []edgeproto.DeploymentCloudletRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowCloudletsForAppDeployment %v\n", data[ii])
		myerr := ShowCloudletsForAppDeployment(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AppApiCmds = []*cobra.Command{
	CreateAppCmd.GenCmd(),
	DeleteAppCmd.GenCmd(),
	UpdateAppCmd.GenCmd(),
	ShowAppCmd.GenCmd(),
	AddAppAutoProvPolicyCmd.GenCmd(),
	RemoveAppAutoProvPolicyCmd.GenCmd(),
	AddAppAlertPolicyCmd.GenCmd(),
	RemoveAppAlertPolicyCmd.GenCmd(),
	ShowCloudletsForAppDeploymentCmd.GenCmd(),
}

var AppKeyRequiredArgs = []string{}
var AppKeyOptionalArgs = []string{
	"organization",
	"name",
	"version",
}
var AppKeyAliasArgs = []string{}
var AppKeyComments = map[string]string{
	"organization": "App developer organization",
	"name":         "App name",
	"version":      "App version",
}
var AppKeySpecialArgs = map[string]string{}
var ConfigFileRequiredArgs = []string{}
var ConfigFileOptionalArgs = []string{
	"kind",
	"config",
}
var ConfigFileAliasArgs = []string{}
var ConfigFileComments = map[string]string{
	"kind":   "Kind (type) of config, i.e. envVarsYaml, helmCustomizationYaml",
	"config": "Config file contents or URI reference",
}
var ConfigFileSpecialArgs = map[string]string{}
var AppRequiredArgs = []string{
	"apporg",
	"appname",
	"appvers",
}
var AppOptionalArgs = []string{
	"imagepath",
	"imagetype",
	"accessports",
	"defaultflavor",
	"authpublickey",
	"command",
	"commandargs",
	"annotations",
	"deployment",
	"deploymentmanifest",
	"deploymentgenerator",
	"androidpackagename",
	"configs:empty",
	"configs:#.kind",
	"configs:#.config",
	"scalewithcluster",
	"internalports",
	"revision",
	"officialfqdn",
	"md5sum",
	"accesstype",
	"autoprovpolicies",
	"templatedelimiter",
	"skiphcports",
	"trusted",
	"requiredoutboundconnections:empty",
	"requiredoutboundconnections:#.protocol",
	"requiredoutboundconnections:#.portrangemin",
	"requiredoutboundconnections:#.portrangemax",
	"requiredoutboundconnections:#.remotecidr",
	"allowserverless",
	"serverlessconfig.vcpus",
	"serverlessconfig.ram",
	"serverlessconfig.minreplicas",
	"serverlessconfig.gpuconfig.type",
	"serverlessconfig.gpuconfig.model",
	"serverlessconfig.gpuconfig.numgpu",
	"serverlessconfig.gpuconfig.ram",
	"vmappostype",
	"alertpolicies",
	"qossessionprofile",
	"qossessionduration",
	"globalid",
	"envvars",
	"secretenvvars",
	"updatelistaction",
}
var AppAliasArgs = []string{
	"apporg=key.organization",
	"appname=key.name",
	"appvers=key.version",
	"defaultflavor=defaultflavor.name",
}
var AppComments = map[string]string{
	"fields":                                 "Fields are used for the Update API to specify which fields to apply",
	"apporg":                                 "App developer organization",
	"appname":                                "App name",
	"appvers":                                "App version",
	"imagepath":                              "URI of where image resides",
	"imagetype":                              "Image type, one of Unknown, Docker, Qcow, Helm, Ovf, Ova",
	"accessports":                            "Comma separated list of protocol:port pairs that the App listens on. Ex: tcp:80,udp:10002. Also supports additional configurations per port: (1) tls (tcp-only) - Enables TLS on specified port. Ex: tcp:443:tls. (2) nginx (udp-only) - Use NGINX LB instead of envoy for specified port. Ex: udp:10001:nginx. (3) maxpktsize (udp-only) - Configures maximum UDP datagram size allowed on port for both upstream/downstream traffic. Ex: udp:10001:maxpktsize=8000.",
	"defaultflavor":                          "Flavor name",
	"authpublickey":                          "Public key used for authentication",
	"command":                                "Command that the container runs to start service, separate multiple commands by a space",
	"commandargs":                            "Command args to append to command, on cli specify multiple times in order, specify commandargs:empty=true to clear",
	"annotations":                            "Annotations is a comma separated map of arbitrary key value pairs, for example: key1=val1,key2=val2,key3=val 3",
	"deployment":                             "Deployment type (kubernetes, docker, or vm)",
	"deploymentmanifest":                     "Deployment manifest is the deployment specific manifest file/config. For docker deployment, this can be a docker-compose or docker run file. For kubernetes deployment, this can be a kubernetes yaml or helm chart file.",
	"deploymentgenerator":                    "Deployment generator target to generate a basic deployment manifest",
	"androidpackagename":                     "Android package name used to match the App name from the Android package",
	"delopt":                                 "Override actions to Controller, one of NoAutoDelete, AutoDelete",
	"configs:empty":                          "Customization files passed through to implementing services, specify configs:empty=true to clear",
	"configs:#.kind":                         "Kind (type) of config, i.e. envVarsYaml, helmCustomizationYaml",
	"configs:#.config":                       "Config file contents or URI reference",
	"scalewithcluster":                       "True indicates App runs on all nodes of the cluster as it scales",
	"internalports":                          "True indicates App is used internally with other Apps only, and no ports are exposed externally",
	"revision":                               "Revision can be specified or defaults to current timestamp when app is updated",
	"officialfqdn":                           "Official FQDN is the FQDN that the app uses to connect by default",
	"md5sum":                                 "MD5Sum of the VM-based app image",
	"autoprovpolicy":                         "(_deprecated_) Auto provisioning policy name",
	"accesstype":                             "(_deprecated_) Access type, one of DefaultForDeployment, Direct, LoadBalancer",
	"deleteprepare":                          "Preparing to be deleted",
	"autoprovpolicies":                       "Auto provisioning policy names, may be specified multiple times, specify autoprovpolicies:empty=true to clear",
	"templatedelimiter":                      "Delimiter to be used for template parsing, defaults to [[ ]]",
	"skiphcports":                            "Comma separated list of protocol:port pairs that we should not run health check on. Should be configured in case app does not always listen on these ports. all can be specified if no health check to be run for this app. Numerical values must be decimal format. i.e. tcp:80,udp:10002",
	"createdat":                              "Created at time",
	"updatedat":                              "Updated at time",
	"trusted":                                "Indicates that an instance of this app can be started on a trusted cloudlet",
	"requiredoutboundconnections:empty":      "Connections this app require to determine if the app is compatible with a trust policy, specify requiredoutboundconnections:empty=true to clear",
	"requiredoutboundconnections:#.protocol": "TCP, UDP, ICMP",
	"requiredoutboundconnections:#.portrangemin": "TCP or UDP port range start",
	"requiredoutboundconnections:#.portrangemax": "TCP or UDP port range end",
	"requiredoutboundconnections:#.remotecidr":   "Remote CIDR X.X.X.X/X for IPv4 or e.g. XXXX:XXXX::XXXX/XX for IPv6",
	"allowserverless":                   "App is allowed to deploy as serverless containers",
	"serverlessconfig.vcpus":            "Virtual CPUs allocation per container when serverless, may be decimal in increments of 0.001",
	"serverlessconfig.ram":              "RAM allocation in megabytes per container when serverless",
	"serverlessconfig.minreplicas":      "Minimum number of replicas when serverless",
	"serverlessconfig.gpuconfig.type":   "GPU Type, one of None, Any, Vgpu, Pci",
	"serverlessconfig.gpuconfig.model":  "Model name or vgpu type",
	"serverlessconfig.gpuconfig.numgpu": "Number of instances",
	"serverlessconfig.gpuconfig.ram":    "required memory in megabytes",
	"vmappostype":                       "OS Type for VM Apps, one of Unknown, Linux, Windows10, Windows2012, Windows2016, Windows2019",
	"alertpolicies":                     "Alert Policies, specify alertpolicies:empty=true to clear",
	"qossessionprofile":                 "Qualifier for the requested latency profile, one of NoPriority, LowLatency, ThroughputDownS, ThroughputDownM, ThroughputDownL",
	"qossessionduration":                "Session duration in seconds. Maximal value of 24 hours is used if not set",
	"globalid":                          "A globally unique id for the App to be used with federation",
	"envvars":                           "Environment variables, specify envvars:empty=true to clear",
	"secretenvvars":                     "Environment variables with sensitive information, stored in encrypted storage, specify secretenvvars:empty=true to clear",
	"updatelistaction":                  "For updating list and map fields, set to add, remove, or replace to define how to resolve specified entries against existing entries",
}
var AppSpecialArgs = map[string]string{
	"alertpolicies":    "StringArray",
	"autoprovpolicies": "StringArray",
	"commandargs":      "StringArray",
	"envvars":          "StringToString",
	"fields":           "StringArray",
	"secretenvvars":    "StringToString",
}
var ServerlessConfigRequiredArgs = []string{}
var ServerlessConfigOptionalArgs = []string{
	"vcpus",
	"ram",
	"minreplicas",
	"gpuconfig.type",
	"gpuconfig.model",
	"gpuconfig.numgpu",
	"gpuconfig.ram",
}
var ServerlessConfigAliasArgs = []string{}
var ServerlessConfigComments = map[string]string{
	"vcpus":            "Virtual CPUs allocation per container when serverless, may be decimal in increments of 0.001",
	"ram":              "RAM allocation in megabytes per container when serverless",
	"minreplicas":      "Minimum number of replicas when serverless",
	"gpuconfig.type":   "GPU Type, one of None, Any, Vgpu, Pci",
	"gpuconfig.model":  "Model name or vgpu type",
	"gpuconfig.numgpu": "Number of instances",
	"gpuconfig.ram":    "required memory in megabytes",
}
var ServerlessConfigSpecialArgs = map[string]string{}
var GpuConfigRequiredArgs = []string{}
var GpuConfigOptionalArgs = []string{
	"type",
	"model",
	"numgpu",
	"ram",
}
var GpuConfigAliasArgs = []string{}
var GpuConfigComments = map[string]string{
	"type":   "GPU Type, one of None, Any, Vgpu, Pci",
	"model":  "Model name or vgpu type",
	"numgpu": "Number of instances",
	"ram":    "required memory in megabytes",
}
var GpuConfigSpecialArgs = map[string]string{}
var AppAutoProvPolicyRequiredArgs = []string{
	"apporg",
	"appname",
	"appvers",
	"autoprovpolicy",
}
var AppAutoProvPolicyOptionalArgs = []string{}
var AppAutoProvPolicyAliasArgs = []string{
	"apporg=appkey.organization",
	"appname=appkey.name",
	"appvers=appkey.version",
}
var AppAutoProvPolicyComments = map[string]string{
	"apporg":         "App developer organization",
	"appname":        "App name",
	"appvers":        "App version",
	"autoprovpolicy": "Auto provisioning policy name",
}
var AppAutoProvPolicySpecialArgs = map[string]string{}
var AppAlertPolicyRequiredArgs = []string{
	"apporg",
	"appname",
	"appvers",
	"alertpolicyname",
}
var AppAlertPolicyOptionalArgs = []string{}
var AppAlertPolicyAliasArgs = []string{
	"apporg=appkey.organization",
	"appname=appkey.name",
	"appvers=appkey.version",
	"alertpolicyname=alertpolicy",
}
var AppAlertPolicyComments = map[string]string{
	"apporg":          "App developer organization",
	"appname":         "App name",
	"appvers":         "App version",
	"alertpolicyname": "Alert name",
}
var AppAlertPolicySpecialArgs = map[string]string{}
var DeploymentCloudletRequestRequiredArgs = []string{}
var DeploymentCloudletRequestOptionalArgs = []string{
	"app.fields",
	"app.key.organization",
	"appname",
	"appvers",
	"app.imagepath",
	"app.imagetype",
	"app.accessports",
	"app.defaultflavor.name",
	"app.authpublickey",
	"app.command",
	"app.commandargs",
	"app.annotations",
	"app.deployment",
	"app.deploymentmanifest",
	"app.deploymentgenerator",
	"app.androidpackagename",
	"app.configs:#.kind",
	"app.configs:#.config",
	"app.scalewithcluster",
	"app.internalports",
	"app.revision",
	"app.officialfqdn",
	"app.md5sum",
	"app.accesstype",
	"app.autoprovpolicies",
	"app.templatedelimiter",
	"app.skiphcports",
	"app.trusted",
	"app.requiredoutboundconnections:#.protocol",
	"app.requiredoutboundconnections:#.portrangemin",
	"app.requiredoutboundconnections:#.portrangemax",
	"app.requiredoutboundconnections:#.remotecidr",
	"app.allowserverless",
	"app.serverlessconfig.vcpus",
	"app.serverlessconfig.ram",
	"app.serverlessconfig.minreplicas",
	"app.serverlessconfig.gpuconfig.type",
	"app.serverlessconfig.gpuconfig.model",
	"app.serverlessconfig.gpuconfig.numgpu",
	"app.serverlessconfig.gpuconfig.ram",
	"app.vmappostype",
	"app.alertpolicies",
	"app.qossessionprofile",
	"app.qossessionduration",
	"app.globalid",
	"app.envvars",
	"app.secretenvvars",
	"app.updatelistaction",
	"dryrundeploy",
	"numnodes",
}
var DeploymentCloudletRequestAliasArgs = []string{
	"appname=app.key.name",
	"appvers=app.key.version",
}
var DeploymentCloudletRequestComments = map[string]string{
	"app.fields":              "Fields are used for the Update API to specify which fields to apply",
	"app.key.organization":    "App developer organization",
	"appname":                 "App name",
	"appvers":                 "App version",
	"app.imagepath":           "URI of where image resides",
	"app.imagetype":           "Image type, one of Unknown, Docker, Qcow, Helm, Ovf, Ova",
	"app.accessports":         "Comma separated list of protocol:port pairs that the App listens on. Ex: tcp:80,udp:10002. Also supports additional configurations per port: (1) tls (tcp-only) - Enables TLS on specified port. Ex: tcp:443:tls. (2) nginx (udp-only) - Use NGINX LB instead of envoy for specified port. Ex: udp:10001:nginx. (3) maxpktsize (udp-only) - Configures maximum UDP datagram size allowed on port for both upstream/downstream traffic. Ex: udp:10001:maxpktsize=8000.",
	"app.defaultflavor.name":  "Flavor name",
	"app.authpublickey":       "Public key used for authentication",
	"app.command":             "Command that the container runs to start service, separate multiple commands by a space",
	"app.commandargs":         "Command args to append to command, on cli specify multiple times in order",
	"app.annotations":         "Annotations is a comma separated map of arbitrary key value pairs, for example: key1=val1,key2=val2,key3=val 3",
	"app.deployment":          "Deployment type (kubernetes, docker, or vm)",
	"app.deploymentmanifest":  "Deployment manifest is the deployment specific manifest file/config. For docker deployment, this can be a docker-compose or docker run file. For kubernetes deployment, this can be a kubernetes yaml or helm chart file.",
	"app.deploymentgenerator": "Deployment generator target to generate a basic deployment manifest",
	"app.androidpackagename":  "Android package name used to match the App name from the Android package",
	"app.delopt":              "Override actions to Controller, one of NoAutoDelete, AutoDelete",
	"app.configs:#.kind":      "Kind (type) of config, i.e. envVarsYaml, helmCustomizationYaml",
	"app.configs:#.config":    "Config file contents or URI reference",
	"app.scalewithcluster":    "True indicates App runs on all nodes of the cluster as it scales",
	"app.internalports":       "True indicates App is used internally with other Apps only, and no ports are exposed externally",
	"app.revision":            "Revision can be specified or defaults to current timestamp when app is updated",
	"app.officialfqdn":        "Official FQDN is the FQDN that the app uses to connect by default",
	"app.md5sum":              "MD5Sum of the VM-based app image",
	"app.autoprovpolicy":      "(_deprecated_) Auto provisioning policy name",
	"app.accesstype":          "(_deprecated_) Access type, one of DefaultForDeployment, Direct, LoadBalancer",
	"app.deleteprepare":       "Preparing to be deleted",
	"app.autoprovpolicies":    "Auto provisioning policy names, may be specified multiple times",
	"app.templatedelimiter":   "Delimiter to be used for template parsing, defaults to [[ ]]",
	"app.skiphcports":         "Comma separated list of protocol:port pairs that we should not run health check on. Should be configured in case app does not always listen on these ports. all can be specified if no health check to be run for this app. Numerical values must be decimal format. i.e. tcp:80,udp:10002",
	"app.createdat":           "Created at time",
	"app.updatedat":           "Updated at time",
	"app.trusted":             "Indicates that an instance of this app can be started on a trusted cloudlet",
	"app.requiredoutboundconnections:#.protocol":     "TCP, UDP, ICMP",
	"app.requiredoutboundconnections:#.portrangemin": "TCP or UDP port range start",
	"app.requiredoutboundconnections:#.portrangemax": "TCP or UDP port range end",
	"app.requiredoutboundconnections:#.remotecidr":   "Remote CIDR X.X.X.X/X for IPv4 or e.g. XXXX:XXXX::XXXX/XX for IPv6",
	"app.allowserverless":                            "App is allowed to deploy as serverless containers",
	"app.serverlessconfig.vcpus":                     "Virtual CPUs allocation per container when serverless, may be decimal in increments of 0.001",
	"app.serverlessconfig.ram":                       "RAM allocation in megabytes per container when serverless",
	"app.serverlessconfig.minreplicas":               "Minimum number of replicas when serverless",
	"app.serverlessconfig.gpuconfig.type":            "GPU Type, one of None, Any, Vgpu, Pci",
	"app.serverlessconfig.gpuconfig.model":           "Model name or vgpu type",
	"app.serverlessconfig.gpuconfig.numgpu":          "Number of instances",
	"app.serverlessconfig.gpuconfig.ram":             "required memory in megabytes",
	"app.vmappostype":                                "OS Type for VM Apps, one of Unknown, Linux, Windows10, Windows2012, Windows2016, Windows2019",
	"app.alertpolicies":                              "Alert Policies",
	"app.qossessionprofile":                          "Qualifier for the requested latency profile, one of NoPriority, LowLatency, ThroughputDownS, ThroughputDownM, ThroughputDownL",
	"app.qossessionduration":                         "Session duration in seconds. Maximal value of 24 hours is used if not set",
	"app.globalid":                                   "A globally unique id for the App to be used with federation",
	"app.envvars":                                    "Environment variables",
	"app.secretenvvars":                              "Environment variables with sensitive information, stored in encrypted storage",
	"app.updatelistaction":                           "For updating list and map fields, set to add, remove, or replace to define how to resolve specified entries against existing entries",
	"dryrundeploy":                                   "Attempt to qualify cloudlet resources for deployment",
	"numnodes":                                       "Optional number of worker VMs in dry run K8s Cluster, default = 2",
}
var DeploymentCloudletRequestSpecialArgs = map[string]string{
	"app.alertpolicies":    "StringArray",
	"app.autoprovpolicies": "StringArray",
	"app.commandargs":      "StringArray",
	"app.envvars":          "StringToString",
	"app.fields":           "StringArray",
	"app.secretenvvars":    "StringToString",
}
var CreateAppRequiredArgs = []string{
	"apporg",
	"appname",
	"appvers",
}
var CreateAppOptionalArgs = []string{
	"imagepath",
	"imagetype",
	"accessports",
	"defaultflavor",
	"authpublickey",
	"command",
	"commandargs",
	"annotations",
	"deployment",
	"deploymentmanifest",
	"deploymentgenerator",
	"androidpackagename",
	"configs:#.kind",
	"configs:#.config",
	"scalewithcluster",
	"internalports",
	"revision",
	"officialfqdn",
	"md5sum",
	"accesstype",
	"autoprovpolicies",
	"templatedelimiter",
	"skiphcports",
	"trusted",
	"requiredoutboundconnections:#.protocol",
	"requiredoutboundconnections:#.portrangemin",
	"requiredoutboundconnections:#.portrangemax",
	"requiredoutboundconnections:#.remotecidr",
	"allowserverless",
	"serverlessconfig.vcpus",
	"serverlessconfig.ram",
	"serverlessconfig.minreplicas",
	"serverlessconfig.gpuconfig.type",
	"serverlessconfig.gpuconfig.model",
	"serverlessconfig.gpuconfig.numgpu",
	"serverlessconfig.gpuconfig.ram",
	"vmappostype",
	"alertpolicies",
	"qossessionprofile",
	"qossessionduration",
	"globalid",
	"envvars",
	"secretenvvars",
}
var DeleteAppRequiredArgs = []string{
	"apporg",
	"appname",
	"appvers",
}
var DeleteAppOptionalArgs = []string{
	"imagepath",
	"imagetype",
	"accessports",
	"defaultflavor",
	"authpublickey",
	"command",
	"commandargs",
	"annotations",
	"deployment",
	"deploymentmanifest",
	"deploymentgenerator",
	"androidpackagename",
	"configs:#.kind",
	"configs:#.config",
	"scalewithcluster",
	"internalports",
	"revision",
	"officialfqdn",
	"md5sum",
	"accesstype",
	"autoprovpolicies",
	"templatedelimiter",
	"skiphcports",
	"trusted",
	"requiredoutboundconnections:#.protocol",
	"requiredoutboundconnections:#.portrangemin",
	"requiredoutboundconnections:#.portrangemax",
	"requiredoutboundconnections:#.remotecidr",
	"allowserverless",
	"serverlessconfig.vcpus",
	"serverlessconfig.ram",
	"serverlessconfig.minreplicas",
	"serverlessconfig.gpuconfig.type",
	"serverlessconfig.gpuconfig.model",
	"serverlessconfig.gpuconfig.numgpu",
	"serverlessconfig.gpuconfig.ram",
	"vmappostype",
	"alertpolicies",
	"qossessionprofile",
	"qossessionduration",
	"globalid",
	"envvars",
	"secretenvvars",
}
var ShowAppRequiredArgs = []string{
	"apporg",
	"appname",
	"appvers",
}
var ShowAppOptionalArgs = []string{
	"imagepath",
	"imagetype",
	"accessports",
	"defaultflavor",
	"authpublickey",
	"command",
	"commandargs",
	"annotations",
	"deployment",
	"deploymentmanifest",
	"deploymentgenerator",
	"androidpackagename",
	"configs:#.kind",
	"configs:#.config",
	"scalewithcluster",
	"internalports",
	"revision",
	"officialfqdn",
	"md5sum",
	"accesstype",
	"autoprovpolicies",
	"templatedelimiter",
	"skiphcports",
	"trusted",
	"requiredoutboundconnections:#.protocol",
	"requiredoutboundconnections:#.portrangemin",
	"requiredoutboundconnections:#.portrangemax",
	"requiredoutboundconnections:#.remotecidr",
	"allowserverless",
	"serverlessconfig.vcpus",
	"serverlessconfig.ram",
	"serverlessconfig.minreplicas",
	"serverlessconfig.gpuconfig.type",
	"serverlessconfig.gpuconfig.model",
	"serverlessconfig.gpuconfig.numgpu",
	"serverlessconfig.gpuconfig.ram",
	"vmappostype",
	"alertpolicies",
	"qossessionprofile",
	"qossessionduration",
	"globalid",
	"envvars",
	"secretenvvars",
}
