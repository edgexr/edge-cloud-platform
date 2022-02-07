// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoprovpolicy.proto

package gencmd

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud/cli"
	_ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
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
func AutoProvInfoHideTags(in *edgeproto.AutoProvInfo) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.NotifyId = 0
	}
}

var AutoProvPolicyApiCmd edgeproto.AutoProvPolicyApiClient

var CreateAutoProvPolicyCmd = &cli.Command{
	Use:          "CreateAutoProvPolicy",
	RequiredArgs: strings.Join(CreateAutoProvPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(CreateAutoProvPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AutoProvPolicyAliasArgs, " "),
	SpecialArgs:  &AutoProvPolicySpecialArgs,
	Comments:     AutoProvPolicyComments,
	ReqData:      &edgeproto.AutoProvPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateAutoProvPolicy,
}

func runCreateAutoProvPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AutoProvPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateAutoProvPolicy(c, obj)
}

func CreateAutoProvPolicy(c *cli.Command, in *edgeproto.AutoProvPolicy) error {
	if AutoProvPolicyApiCmd == nil {
		return fmt.Errorf("AutoProvPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AutoProvPolicyApiCmd.CreateAutoProvPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateAutoProvPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateAutoProvPolicys(c *cli.Command, data []edgeproto.AutoProvPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateAutoProvPolicy %v\n", data[ii])
		myerr := CreateAutoProvPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteAutoProvPolicyCmd = &cli.Command{
	Use:          "DeleteAutoProvPolicy",
	RequiredArgs: strings.Join(AutoProvPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AutoProvPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AutoProvPolicyAliasArgs, " "),
	SpecialArgs:  &AutoProvPolicySpecialArgs,
	Comments:     AutoProvPolicyComments,
	ReqData:      &edgeproto.AutoProvPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteAutoProvPolicy,
}

func runDeleteAutoProvPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AutoProvPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteAutoProvPolicy(c, obj)
}

func DeleteAutoProvPolicy(c *cli.Command, in *edgeproto.AutoProvPolicy) error {
	if AutoProvPolicyApiCmd == nil {
		return fmt.Errorf("AutoProvPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AutoProvPolicyApiCmd.DeleteAutoProvPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteAutoProvPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteAutoProvPolicys(c *cli.Command, data []edgeproto.AutoProvPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteAutoProvPolicy %v\n", data[ii])
		myerr := DeleteAutoProvPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateAutoProvPolicyCmd = &cli.Command{
	Use:          "UpdateAutoProvPolicy",
	RequiredArgs: strings.Join(AutoProvPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AutoProvPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AutoProvPolicyAliasArgs, " "),
	SpecialArgs:  &AutoProvPolicySpecialArgs,
	Comments:     AutoProvPolicyComments,
	ReqData:      &edgeproto.AutoProvPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runUpdateAutoProvPolicy,
}

func runUpdateAutoProvPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AutoProvPolicy)
	jsonMap, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	obj.Fields = cli.GetSpecifiedFields(jsonMap, c.ReqData)
	return UpdateAutoProvPolicy(c, obj)
}

func UpdateAutoProvPolicy(c *cli.Command, in *edgeproto.AutoProvPolicy) error {
	if AutoProvPolicyApiCmd == nil {
		return fmt.Errorf("AutoProvPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AutoProvPolicyApiCmd.UpdateAutoProvPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateAutoProvPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func UpdateAutoProvPolicys(c *cli.Command, data []edgeproto.AutoProvPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateAutoProvPolicy %v\n", data[ii])
		myerr := UpdateAutoProvPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowAutoProvPolicyCmd = &cli.Command{
	Use:          "ShowAutoProvPolicy",
	OptionalArgs: strings.Join(append(AutoProvPolicyRequiredArgs, AutoProvPolicyOptionalArgs...), " "),
	AliasArgs:    strings.Join(AutoProvPolicyAliasArgs, " "),
	SpecialArgs:  &AutoProvPolicySpecialArgs,
	Comments:     AutoProvPolicyComments,
	ReqData:      &edgeproto.AutoProvPolicy{},
	ReplyData:    &edgeproto.AutoProvPolicy{},
	Run:          runShowAutoProvPolicy,
}

func runShowAutoProvPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AutoProvPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowAutoProvPolicy(c, obj)
}

func ShowAutoProvPolicy(c *cli.Command, in *edgeproto.AutoProvPolicy) error {
	if AutoProvPolicyApiCmd == nil {
		return fmt.Errorf("AutoProvPolicyApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AutoProvPolicyApiCmd.ShowAutoProvPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowAutoProvPolicy failed: %s", errstr)
	}

	objs := make([]*edgeproto.AutoProvPolicy, 0)
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
			return fmt.Errorf("ShowAutoProvPolicy recv failed: %s", errstr)
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
func ShowAutoProvPolicys(c *cli.Command, data []edgeproto.AutoProvPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowAutoProvPolicy %v\n", data[ii])
		myerr := ShowAutoProvPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AddAutoProvPolicyCloudletCmd = &cli.Command{
	Use:          "AddAutoProvPolicyCloudlet",
	RequiredArgs: strings.Join(AutoProvPolicyCloudletRequiredArgs, " "),
	OptionalArgs: strings.Join(AutoProvPolicyCloudletOptionalArgs, " "),
	AliasArgs:    strings.Join(AutoProvPolicyCloudletAliasArgs, " "),
	SpecialArgs:  &AutoProvPolicyCloudletSpecialArgs,
	Comments:     AutoProvPolicyCloudletComments,
	ReqData:      &edgeproto.AutoProvPolicyCloudlet{},
	ReplyData:    &edgeproto.Result{},
	Run:          runAddAutoProvPolicyCloudlet,
}

func runAddAutoProvPolicyCloudlet(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AutoProvPolicyCloudlet)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return AddAutoProvPolicyCloudlet(c, obj)
}

func AddAutoProvPolicyCloudlet(c *cli.Command, in *edgeproto.AutoProvPolicyCloudlet) error {
	if AutoProvPolicyApiCmd == nil {
		return fmt.Errorf("AutoProvPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AutoProvPolicyApiCmd.AddAutoProvPolicyCloudlet(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("AddAutoProvPolicyCloudlet failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func AddAutoProvPolicyCloudlets(c *cli.Command, data []edgeproto.AutoProvPolicyCloudlet, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("AddAutoProvPolicyCloudlet %v\n", data[ii])
		myerr := AddAutoProvPolicyCloudlet(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var RemoveAutoProvPolicyCloudletCmd = &cli.Command{
	Use:          "RemoveAutoProvPolicyCloudlet",
	RequiredArgs: strings.Join(AutoProvPolicyCloudletRequiredArgs, " "),
	OptionalArgs: strings.Join(AutoProvPolicyCloudletOptionalArgs, " "),
	AliasArgs:    strings.Join(AutoProvPolicyCloudletAliasArgs, " "),
	SpecialArgs:  &AutoProvPolicyCloudletSpecialArgs,
	Comments:     AutoProvPolicyCloudletComments,
	ReqData:      &edgeproto.AutoProvPolicyCloudlet{},
	ReplyData:    &edgeproto.Result{},
	Run:          runRemoveAutoProvPolicyCloudlet,
}

func runRemoveAutoProvPolicyCloudlet(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AutoProvPolicyCloudlet)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return RemoveAutoProvPolicyCloudlet(c, obj)
}

func RemoveAutoProvPolicyCloudlet(c *cli.Command, in *edgeproto.AutoProvPolicyCloudlet) error {
	if AutoProvPolicyApiCmd == nil {
		return fmt.Errorf("AutoProvPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AutoProvPolicyApiCmd.RemoveAutoProvPolicyCloudlet(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("RemoveAutoProvPolicyCloudlet failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func RemoveAutoProvPolicyCloudlets(c *cli.Command, data []edgeproto.AutoProvPolicyCloudlet, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("RemoveAutoProvPolicyCloudlet %v\n", data[ii])
		myerr := RemoveAutoProvPolicyCloudlet(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AutoProvPolicyApiCmds = []*cobra.Command{
	CreateAutoProvPolicyCmd.GenCmd(),
	DeleteAutoProvPolicyCmd.GenCmd(),
	UpdateAutoProvPolicyCmd.GenCmd(),
	ShowAutoProvPolicyCmd.GenCmd(),
	AddAutoProvPolicyCloudletCmd.GenCmd(),
	RemoveAutoProvPolicyCloudletCmd.GenCmd(),
}

var AutoProvPolicyRequiredArgs = []string{
	"apporg",
	"name",
}
var AutoProvPolicyOptionalArgs = []string{
	"deployclientcount",
	"deployintervalcount",
	"cloudlets:empty",
	"cloudlets:#.key.organization",
	"cloudlets:#.key.name",
	"cloudlets:#.key.federatedorganization",
	"minactiveinstances",
	"maxinstances",
	"undeployclientcount",
	"undeployintervalcount",
}
var AutoProvPolicyAliasArgs = []string{
	"apporg=key.organization",
	"name=key.name",
}
var AutoProvPolicyComments = map[string]string{
	"fields":                                "Fields are used for the Update API to specify which fields to apply",
	"apporg":                                "Name of the organization for the cluster that this policy will apply to",
	"name":                                  "Policy name",
	"deployclientcount":                     "Minimum number of clients within the auto deploy interval to trigger deployment",
	"deployintervalcount":                   "Number of intervals to check before triggering deployment",
	"cloudlets:empty":                       "Allowed deployment locations, specify cloudlets:empty=true to clear",
	"cloudlets:#.key.organization":          "Organization of the cloudlet site",
	"cloudlets:#.key.name":                  "Name of the cloudlet",
	"cloudlets:#.key.federatedorganization": "Federated operator organization who shared this cloudlet",
	"cloudlets:#.loc.latitude":              "Latitude in WGS 84 coordinates",
	"cloudlets:#.loc.longitude":             "Longitude in WGS 84 coordinates",
	"cloudlets:#.loc.horizontalaccuracy":    "Horizontal accuracy (radius in meters)",
	"cloudlets:#.loc.verticalaccuracy":      "Vertical accuracy (meters)",
	"cloudlets:#.loc.altitude":              "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"cloudlets:#.loc.course":                "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"cloudlets:#.loc.speed":                 "Speed (IOS) / velocity (Android) (meters/sec)",
	"cloudlets:#.loc.timestamp":             "Timestamp",
	"minactiveinstances":                    "Minimum number of active instances for High-Availability",
	"maxinstances":                          "Maximum number of instances (active or not)",
	"undeployclientcount":                   "Number of active clients for the undeploy interval below which trigers undeployment, 0 (default) disables auto undeploy",
	"undeployintervalcount":                 "Number of intervals to check before triggering undeployment",
	"deleteprepare":                         "Preparing to be deleted",
}
var AutoProvPolicySpecialArgs = map[string]string{
	"fields": "StringArray",
}
var AutoProvCloudletRequiredArgs = []string{
	"key.organization",
	"key.name",
	"key.federatedorganization",
}
var AutoProvCloudletOptionalArgs = []string{
	"loc.latitude",
	"loc.longitude",
	"loc.horizontalaccuracy",
	"loc.verticalaccuracy",
	"loc.altitude",
	"loc.course",
	"loc.speed",
	"loc.timestamp",
}
var AutoProvCloudletAliasArgs = []string{}
var AutoProvCloudletComments = map[string]string{
	"key.organization":          "Organization of the cloudlet site",
	"key.name":                  "Name of the cloudlet",
	"key.federatedorganization": "Federated operator organization who shared this cloudlet",
	"loc.latitude":              "Latitude in WGS 84 coordinates",
	"loc.longitude":             "Longitude in WGS 84 coordinates",
	"loc.horizontalaccuracy":    "Horizontal accuracy (radius in meters)",
	"loc.verticalaccuracy":      "Vertical accuracy (meters)",
	"loc.altitude":              "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"loc.course":                "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"loc.speed":                 "Speed (IOS) / velocity (Android) (meters/sec)",
	"loc.timestamp":             "Timestamp",
}
var AutoProvCloudletSpecialArgs = map[string]string{}
var AutoProvCountRequiredArgs = []string{}
var AutoProvCountOptionalArgs = []string{
	"appkey.organization",
	"appkey.name",
	"appkey.version",
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"count",
	"processnow",
	"deploynowkey.clusterkey.name",
	"deploynowkey.cloudletkey.organization",
	"deploynowkey.cloudletkey.name",
	"deploynowkey.cloudletkey.federatedorganization",
	"deploynowkey.organization",
}
var AutoProvCountAliasArgs = []string{}
var AutoProvCountComments = map[string]string{
	"appkey.organization":                            "App developer organization",
	"appkey.name":                                    "App name",
	"appkey.version":                                 "App version",
	"cloudletkey.organization":                       "Organization of the cloudlet site",
	"cloudletkey.name":                               "Name of the cloudlet",
	"cloudletkey.federatedorganization":              "Federated operator organization who shared this cloudlet",
	"count":                                          "FindCloudlet client count",
	"processnow":                                     "Process count immediately",
	"deploynowkey.clusterkey.name":                   "Cluster name",
	"deploynowkey.cloudletkey.organization":          "Organization of the cloudlet site",
	"deploynowkey.cloudletkey.name":                  "Name of the cloudlet",
	"deploynowkey.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"deploynowkey.organization":                      "Name of Developer organization that this cluster belongs to",
}
var AutoProvCountSpecialArgs = map[string]string{}
var AutoProvCountsRequiredArgs = []string{}
var AutoProvCountsOptionalArgs = []string{
	"dmenodename",
	"timestamp.seconds",
	"timestamp.nanos",
	"counts:#.appkey.organization",
	"counts:#.appkey.name",
	"counts:#.appkey.version",
	"counts:#.cloudletkey.organization",
	"counts:#.cloudletkey.name",
	"counts:#.cloudletkey.federatedorganization",
	"counts:#.count",
	"counts:#.processnow",
	"counts:#.deploynowkey.clusterkey.name",
	"counts:#.deploynowkey.cloudletkey.organization",
	"counts:#.deploynowkey.cloudletkey.name",
	"counts:#.deploynowkey.cloudletkey.federatedorganization",
	"counts:#.deploynowkey.organization",
}
var AutoProvCountsAliasArgs = []string{}
var AutoProvCountsComments = map[string]string{
	"dmenodename":                                             "DME node name",
	"timestamp.seconds":                                       "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"timestamp.nanos":                                         "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"counts:#.appkey.organization":                            "App developer organization",
	"counts:#.appkey.name":                                    "App name",
	"counts:#.appkey.version":                                 "App version",
	"counts:#.cloudletkey.organization":                       "Organization of the cloudlet site",
	"counts:#.cloudletkey.name":                               "Name of the cloudlet",
	"counts:#.cloudletkey.federatedorganization":              "Federated operator organization who shared this cloudlet",
	"counts:#.count":                                          "FindCloudlet client count",
	"counts:#.processnow":                                     "Process count immediately",
	"counts:#.deploynowkey.clusterkey.name":                   "Cluster name",
	"counts:#.deploynowkey.cloudletkey.organization":          "Organization of the cloudlet site",
	"counts:#.deploynowkey.cloudletkey.name":                  "Name of the cloudlet",
	"counts:#.deploynowkey.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"counts:#.deploynowkey.organization":                      "Name of Developer organization that this cluster belongs to",
}
var AutoProvCountsSpecialArgs = map[string]string{}
var AutoProvPolicyCloudletRequiredArgs = []string{
	"apporg",
	"name",
}
var AutoProvPolicyCloudletOptionalArgs = []string{
	"cloudletorg",
	"cloudlet",
	"federatedorg",
}
var AutoProvPolicyCloudletAliasArgs = []string{
	"apporg=key.organization",
	"name=key.name",
	"cloudletorg=cloudletkey.organization",
	"cloudlet=cloudletkey.name",
	"federatedorg=cloudletkey.federatedorganization",
}
var AutoProvPolicyCloudletComments = map[string]string{
	"apporg":       "Name of the organization for the cluster that this policy will apply to",
	"name":         "Policy name",
	"cloudletorg":  "Organization of the cloudlet site",
	"cloudlet":     "Name of the cloudlet",
	"federatedorg": "Federated operator organization who shared this cloudlet",
}
var AutoProvPolicyCloudletSpecialArgs = map[string]string{}
var AutoProvInfoRequiredArgs = []string{
	"key.organization",
	"key.name",
	"key.federatedorganization",
}
var AutoProvInfoOptionalArgs = []string{
	"notifyid",
	"maintenancestate",
	"completed",
	"errors",
}
var AutoProvInfoAliasArgs = []string{}
var AutoProvInfoComments = map[string]string{
	"fields":                    "Fields are used for the Update API to specify which fields to apply",
	"key.organization":          "Organization of the cloudlet site",
	"key.name":                  "Name of the cloudlet",
	"key.federatedorganization": "Federated operator organization who shared this cloudlet",
	"notifyid":                  "Id of client assigned by server (internal use only)",
	"maintenancestate":          "failover result state, one of NormalOperation, MaintenanceStart, MaintenanceStartNoFailover",
	"completed":                 "Failover actions done if any",
	"errors":                    "Errors if any",
}
var AutoProvInfoSpecialArgs = map[string]string{
	"completed": "StringArray",
	"errors":    "StringArray",
	"fields":    "StringArray",
}
var CreateAutoProvPolicyRequiredArgs = []string{
	"apporg",
	"name",
}
var CreateAutoProvPolicyOptionalArgs = []string{
	"deployclientcount",
	"deployintervalcount",
	"cloudlets:#.key.organization",
	"cloudlets:#.key.name",
	"cloudlets:#.key.federatedorganization",
	"minactiveinstances",
	"maxinstances",
	"undeployclientcount",
	"undeployintervalcount",
}
