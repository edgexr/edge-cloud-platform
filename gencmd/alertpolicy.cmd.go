// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alertpolicy.proto

package gencmd

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud/cli"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	_ "github.com/edgexr/edge-cloud/protogen"
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
func AlertPolicyHideTags(in *edgeproto.AlertPolicy) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.DeletePrepare = false
	}
}

var AlertPolicyApiCmd edgeproto.AlertPolicyApiClient

var CreateAlertPolicyCmd = &cli.Command{
	Use:          "CreateAlertPolicy",
	RequiredArgs: strings.Join(CreateAlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(CreateAlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     AlertPolicyComments,
	ReqData:      &edgeproto.AlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateAlertPolicy,
}

func runCreateAlertPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AlertPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateAlertPolicy(c, obj)
}

func CreateAlertPolicy(c *cli.Command, in *edgeproto.AlertPolicy) error {
	if AlertPolicyApiCmd == nil {
		return fmt.Errorf("AlertPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AlertPolicyApiCmd.CreateAlertPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateAlertPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateAlertPolicys(c *cli.Command, data []edgeproto.AlertPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateAlertPolicy %v\n", data[ii])
		myerr := CreateAlertPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteAlertPolicyCmd = &cli.Command{
	Use:          "DeleteAlertPolicy",
	RequiredArgs: strings.Join(AlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     AlertPolicyComments,
	ReqData:      &edgeproto.AlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteAlertPolicy,
}

func runDeleteAlertPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AlertPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteAlertPolicy(c, obj)
}

func DeleteAlertPolicy(c *cli.Command, in *edgeproto.AlertPolicy) error {
	if AlertPolicyApiCmd == nil {
		return fmt.Errorf("AlertPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AlertPolicyApiCmd.DeleteAlertPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteAlertPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteAlertPolicys(c *cli.Command, data []edgeproto.AlertPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteAlertPolicy %v\n", data[ii])
		myerr := DeleteAlertPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateAlertPolicyCmd = &cli.Command{
	Use:          "UpdateAlertPolicy",
	RequiredArgs: strings.Join(AlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     AlertPolicyComments,
	ReqData:      &edgeproto.AlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Run:          runUpdateAlertPolicy,
}

func runUpdateAlertPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AlertPolicy)
	jsonMap, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	obj.Fields = cli.GetSpecifiedFields(jsonMap, c.ReqData)
	return UpdateAlertPolicy(c, obj)
}

func UpdateAlertPolicy(c *cli.Command, in *edgeproto.AlertPolicy) error {
	if AlertPolicyApiCmd == nil {
		return fmt.Errorf("AlertPolicyApi client not initialized")
	}
	ctx := context.Background()
	obj, err := AlertPolicyApiCmd.UpdateAlertPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateAlertPolicy failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func UpdateAlertPolicys(c *cli.Command, data []edgeproto.AlertPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateAlertPolicy %v\n", data[ii])
		myerr := UpdateAlertPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowAlertPolicyCmd = &cli.Command{
	Use:          "ShowAlertPolicy",
	OptionalArgs: strings.Join(append(AlertPolicyRequiredArgs, AlertPolicyOptionalArgs...), " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     AlertPolicyComments,
	ReqData:      &edgeproto.AlertPolicy{},
	ReplyData:    &edgeproto.AlertPolicy{},
	Run:          runShowAlertPolicy,
}

func runShowAlertPolicy(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.AlertPolicy)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowAlertPolicy(c, obj)
}

func ShowAlertPolicy(c *cli.Command, in *edgeproto.AlertPolicy) error {
	if AlertPolicyApiCmd == nil {
		return fmt.Errorf("AlertPolicyApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AlertPolicyApiCmd.ShowAlertPolicy(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowAlertPolicy failed: %s", errstr)
	}

	objs := make([]*edgeproto.AlertPolicy, 0)
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
			return fmt.Errorf("ShowAlertPolicy recv failed: %s", errstr)
		}
		AlertPolicyHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowAlertPolicys(c *cli.Command, data []edgeproto.AlertPolicy, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowAlertPolicy %v\n", data[ii])
		myerr := ShowAlertPolicy(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AlertPolicyApiCmds = []*cobra.Command{
	CreateAlertPolicyCmd.GenCmd(),
	DeleteAlertPolicyCmd.GenCmd(),
	UpdateAlertPolicyCmd.GenCmd(),
	ShowAlertPolicyCmd.GenCmd(),
}

var AlertPolicyKeyRequiredArgs = []string{}
var AlertPolicyKeyOptionalArgs = []string{
	"organization",
	"name",
}
var AlertPolicyKeyAliasArgs = []string{}
var AlertPolicyKeyComments = map[string]string{
	"organization": "Name of the organization for the app that this alert can be applied to",
	"name":         "Alert Policy name",
}
var AlertPolicyKeySpecialArgs = map[string]string{}
var AlertPolicyRequiredArgs = []string{
	"alertorg",
	"name",
}
var AlertPolicyOptionalArgs = []string{
	"cpuutilization",
	"memutilization",
	"diskutilization",
	"activeconnections",
	"severity",
	"triggertime",
	"labels",
	"annotations",
	"description",
}
var AlertPolicyAliasArgs = []string{
	"alertorg=key.organization",
	"name=key.name",
	"cpuutilization=cpuutilizationlimit",
	"memutilization=memutilizationlimit",
	"diskutilization=diskutilizationlimit",
	"activeconnections=activeconnlimit",
	"triggertime=triggertime",
}
var AlertPolicyComments = map[string]string{
	"alertorg":          "Name of the organization for the app that this alert can be applied to",
	"name":              "Alert Policy name",
	"cpuutilization":    "Container or pod CPU utilization rate(percentage) across all nodes. Valid values 1-100",
	"memutilization":    "Container or pod memory utilization rate(percentage) across all nodes. Valid values 1-100",
	"diskutilization":   "Container or pod disk utilization rate(percentage) across all nodes. Valid values 1-100",
	"activeconnections": "Active Connections alert threshold. Valid values 1-4294967295",
	"severity":          "Alert severity level - one of info, warning, error",
	"triggertime":       "Duration for which alert interval is active (max 72 hours)",
	"labels":            "Additional Labels, specify labels:empty=true to clear",
	"annotations":       "Additional Annotations for extra information about the alert, specify annotations:empty=true to clear",
	"description":       "Description of the alert policy",
	"deleteprepare":     "Preparing to be deleted",
}
var AlertPolicySpecialArgs = map[string]string{
	"annotations": "StringToString",
	"fields":      "StringArray",
	"labels":      "StringToString",
}
var CreateAlertPolicyRequiredArgs = []string{
	"alertorg",
	"name",
	"severity",
}
var CreateAlertPolicyOptionalArgs = []string{
	"cpuutilization",
	"memutilization",
	"diskutilization",
	"activeconnections",
	"triggertime",
	"labels",
	"annotations",
	"description",
}
