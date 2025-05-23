// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

package gencmd

import (
	"context"
	fmt "fmt"
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
func DebugRequestHideTags(in *edgeproto.DebugRequest) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.Node.Name = ""
	}
}

func DebugReplyHideTags(in *edgeproto.DebugReply) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.Node.Name = ""
	}
}

func DebugDataHideTags(in *edgeproto.DebugData) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	for i0 := 0; i0 < len(in.Requests); i0++ {
		if _, found := tags["nocmp"]; found {
			in.Requests[i0].Node.Name = ""
		}
	}
}

var DebugApiCmd edgeproto.DebugApiClient

var EnableDebugLevelsCmd = &cli.Command{
	Use:          "EnableDebugLevels",
	RequiredArgs: strings.Join(EnableDebugLevelsRequiredArgs, " "),
	OptionalArgs: strings.Join(EnableDebugLevelsOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     DebugRequestComments,
	ReqData:      &edgeproto.DebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Run:          runEnableDebugLevels,
}

func runEnableDebugLevels(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.DebugRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return EnableDebugLevels(c, obj)
}

func EnableDebugLevels(c *cli.Command, in *edgeproto.DebugRequest) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	stream, err := DebugApiCmd.EnableDebugLevels(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("EnableDebugLevels failed: %s", errstr)
	}

	objs := make([]*edgeproto.DebugReply, 0)
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
			return fmt.Errorf("EnableDebugLevels recv failed: %s", errstr)
		}
		DebugReplyHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func EnableDebugLevelss(c *cli.Command, data []edgeproto.DebugRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("EnableDebugLevels %v\n", data[ii])
		myerr := EnableDebugLevels(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DisableDebugLevelsCmd = &cli.Command{
	Use:          "DisableDebugLevels",
	RequiredArgs: strings.Join(DisableDebugLevelsRequiredArgs, " "),
	OptionalArgs: strings.Join(DisableDebugLevelsOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     DebugRequestComments,
	ReqData:      &edgeproto.DebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Run:          runDisableDebugLevels,
}

func runDisableDebugLevels(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.DebugRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DisableDebugLevels(c, obj)
}

func DisableDebugLevels(c *cli.Command, in *edgeproto.DebugRequest) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	stream, err := DebugApiCmd.DisableDebugLevels(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DisableDebugLevels failed: %s", errstr)
	}

	objs := make([]*edgeproto.DebugReply, 0)
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
			return fmt.Errorf("DisableDebugLevels recv failed: %s", errstr)
		}
		DebugReplyHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DisableDebugLevelss(c *cli.Command, data []edgeproto.DebugRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DisableDebugLevels %v\n", data[ii])
		myerr := DisableDebugLevels(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowDebugLevelsCmd = &cli.Command{
	Use:          "ShowDebugLevels",
	RequiredArgs: strings.Join(ShowDebugLevelsRequiredArgs, " "),
	OptionalArgs: strings.Join(ShowDebugLevelsOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     DebugRequestComments,
	ReqData:      &edgeproto.DebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Run:          runShowDebugLevels,
}

func runShowDebugLevels(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.DebugRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowDebugLevels(c, obj)
}

func ShowDebugLevels(c *cli.Command, in *edgeproto.DebugRequest) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	stream, err := DebugApiCmd.ShowDebugLevels(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowDebugLevels failed: %s", errstr)
	}

	objs := make([]*edgeproto.DebugReply, 0)
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
			return fmt.Errorf("ShowDebugLevels recv failed: %s", errstr)
		}
		DebugReplyHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowDebugLevelss(c *cli.Command, data []edgeproto.DebugRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowDebugLevels %v\n", data[ii])
		myerr := ShowDebugLevels(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var RunDebugCmd = &cli.Command{
	Use:          "RunDebug",
	RequiredArgs: strings.Join(RunDebugRequiredArgs, " "),
	OptionalArgs: strings.Join(RunDebugOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     DebugRequestComments,
	ReqData:      &edgeproto.DebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Run:          runRunDebug,
}

func runRunDebug(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.DebugRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return RunDebug(c, obj)
}

func RunDebug(c *cli.Command, in *edgeproto.DebugRequest) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	stream, err := DebugApiCmd.RunDebug(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("RunDebug failed: %s", errstr)
	}

	objs := make([]*edgeproto.DebugReply, 0)
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
			return fmt.Errorf("RunDebug recv failed: %s", errstr)
		}
		DebugReplyHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func RunDebugs(c *cli.Command, data []edgeproto.DebugRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("RunDebug %v\n", data[ii])
		myerr := RunDebug(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DebugApiCmds = []*cobra.Command{
	EnableDebugLevelsCmd.GenCmd(),
	DisableDebugLevelsCmd.GenCmd(),
	ShowDebugLevelsCmd.GenCmd(),
	RunDebugCmd.GenCmd(),
}

var DebugRequestRequiredArgs = []string{}
var DebugRequestOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"levels",
	"cmd",
	"pretty",
	"id",
	"args",
	"timeout",
}
var DebugRequestAliasArgs = []string{
	"name=node.name",
	"type=node.type",
	"organization=node.cloudletkey.organization",
	"cloudlet=node.cloudletkey.name",
	"region=node.region",
	"cmd=cmd",
}
var DebugRequestComments = map[string]string{
	"name":                                   "Name or hostname of service node",
	"type":                                   "Service node type",
	"organization":                           "Organization of the cloudlet site",
	"cloudlet":                               "Name of the cloudlet",
	"node.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"region":                                 "Region the node is in",
	"levels":                                 "Comma separated list of debug level names: etcd,api,notify,dmereq,locapi,infra,metrics,upgrade,info,sampled,fedapi",
	"cmd":                                    "Debug command (use help to see available commands)",
	"pretty":                                 "if possible, make output pretty",
	"id":                                     "Id used internally",
	"args":                                   "Additional arguments for cmd",
	"timeout":                                "custom timeout (duration, defaults to 10s)",
}
var DebugRequestSpecialArgs = map[string]string{}
var DebugReplyRequiredArgs = []string{}
var DebugReplyOptionalArgs = []string{
	"node.name",
	"node.type",
	"node.cloudletkey.organization",
	"node.cloudletkey.name",
	"node.cloudletkey.federatedorganization",
	"node.region",
	"output",
	"id",
}
var DebugReplyAliasArgs = []string{}
var DebugReplyComments = map[string]string{
	"node.name":                              "Name or hostname of service node",
	"node.type":                              "Service node type",
	"node.cloudletkey.organization":          "Organization of the cloudlet site",
	"node.cloudletkey.name":                  "Name of the cloudlet",
	"node.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"node.region":                            "Region the node is in",
	"output":                                 "Debug output, if any",
	"id":                                     "Id used internally",
}
var DebugReplySpecialArgs = map[string]string{}
var DebugDataRequiredArgs = []string{}
var DebugDataOptionalArgs = []string{
	"requests:#.node.name",
	"requests:#.node.type",
	"requests:#.node.cloudletkey.organization",
	"requests:#.node.cloudletkey.name",
	"requests:#.node.cloudletkey.federatedorganization",
	"requests:#.node.region",
	"requests:#.levels",
	"requests:#.cmd",
	"requests:#.pretty",
	"requests:#.id",
	"requests:#.args",
	"requests:#.timeout",
}
var DebugDataAliasArgs = []string{}
var DebugDataComments = map[string]string{
	"requests:#.node.name":                              "Name or hostname of service node",
	"requests:#.node.type":                              "Service node type",
	"requests:#.node.cloudletkey.organization":          "Organization of the cloudlet site",
	"requests:#.node.cloudletkey.name":                  "Name of the cloudlet",
	"requests:#.node.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"requests:#.node.region":                            "Region the node is in",
	"requests:#.levels":                                 "Comma separated list of debug level names: etcd,api,notify,dmereq,locapi,infra,metrics,upgrade,info,sampled,fedapi",
	"requests:#.cmd":                                    "Debug command (use help to see available commands)",
	"requests:#.pretty":                                 "if possible, make output pretty",
	"requests:#.id":                                     "Id used internally",
	"requests:#.args":                                   "Additional arguments for cmd",
	"requests:#.timeout":                                "custom timeout (duration, defaults to 10s)",
}
var DebugDataSpecialArgs = map[string]string{}
var EnableDebugLevelsRequiredArgs = []string{
	"levels",
}
var EnableDebugLevelsOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var DisableDebugLevelsRequiredArgs = []string{
	"levels",
}
var DisableDebugLevelsOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var ShowDebugLevelsRequiredArgs = []string{}
var ShowDebugLevelsOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var RunDebugRequiredArgs = []string{
	"cmd",
}
var RunDebugOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
