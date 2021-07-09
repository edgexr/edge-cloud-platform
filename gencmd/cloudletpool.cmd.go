// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudletpool.proto

package gencmd

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud/cli"
	_ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	distributed_match_engine "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
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
func CloudletPoolHideTags(in *edgeproto.CloudletPool) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["timestamp"]; found {
		in.CreatedAt = distributed_match_engine.Timestamp{}
	}
	if _, found := tags["timestamp"]; found {
		in.UpdatedAt = distributed_match_engine.Timestamp{}
	}
}

var CloudletPoolApiCmd edgeproto.CloudletPoolApiClient

var CreateCloudletPoolCmd = &cli.Command{
	Use:          "CreateCloudletPool",
	RequiredArgs: strings.Join(CloudletPoolRequiredArgs, " "),
	OptionalArgs: strings.Join(CloudletPoolOptionalArgs, " "),
	AliasArgs:    strings.Join(CloudletPoolAliasArgs, " "),
	SpecialArgs:  &CloudletPoolSpecialArgs,
	Comments:     CloudletPoolComments,
	ReqData:      &edgeproto.CloudletPool{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateCloudletPool,
}

func runCreateCloudletPool(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.CloudletPool)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateCloudletPool(c, obj)
}

func CreateCloudletPool(c *cli.Command, in *edgeproto.CloudletPool) error {
	if CloudletPoolApiCmd == nil {
		return fmt.Errorf("CloudletPoolApi client not initialized")
	}
	ctx := context.Background()
	obj, err := CloudletPoolApiCmd.CreateCloudletPool(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateCloudletPool failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateCloudletPools(c *cli.Command, data []edgeproto.CloudletPool, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateCloudletPool %v\n", data[ii])
		myerr := CreateCloudletPool(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteCloudletPoolCmd = &cli.Command{
	Use:          "DeleteCloudletPool",
	RequiredArgs: strings.Join(CloudletPoolRequiredArgs, " "),
	OptionalArgs: strings.Join(CloudletPoolOptionalArgs, " "),
	AliasArgs:    strings.Join(CloudletPoolAliasArgs, " "),
	SpecialArgs:  &CloudletPoolSpecialArgs,
	Comments:     CloudletPoolComments,
	ReqData:      &edgeproto.CloudletPool{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteCloudletPool,
}

func runDeleteCloudletPool(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.CloudletPool)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteCloudletPool(c, obj)
}

func DeleteCloudletPool(c *cli.Command, in *edgeproto.CloudletPool) error {
	if CloudletPoolApiCmd == nil {
		return fmt.Errorf("CloudletPoolApi client not initialized")
	}
	ctx := context.Background()
	obj, err := CloudletPoolApiCmd.DeleteCloudletPool(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteCloudletPool failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteCloudletPools(c *cli.Command, data []edgeproto.CloudletPool, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteCloudletPool %v\n", data[ii])
		myerr := DeleteCloudletPool(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateCloudletPoolCmd = &cli.Command{
	Use:          "UpdateCloudletPool",
	RequiredArgs: strings.Join(CloudletPoolRequiredArgs, " "),
	OptionalArgs: strings.Join(CloudletPoolOptionalArgs, " "),
	AliasArgs:    strings.Join(CloudletPoolAliasArgs, " "),
	SpecialArgs:  &CloudletPoolSpecialArgs,
	Comments:     CloudletPoolComments,
	ReqData:      &edgeproto.CloudletPool{},
	ReplyData:    &edgeproto.Result{},
	Run:          runUpdateCloudletPool,
}

func runUpdateCloudletPool(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.CloudletPool)
	jsonMap, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	obj.Fields = cli.GetSpecifiedFields(jsonMap, c.ReqData)
	return UpdateCloudletPool(c, obj)
}

func UpdateCloudletPool(c *cli.Command, in *edgeproto.CloudletPool) error {
	if CloudletPoolApiCmd == nil {
		return fmt.Errorf("CloudletPoolApi client not initialized")
	}
	ctx := context.Background()
	obj, err := CloudletPoolApiCmd.UpdateCloudletPool(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateCloudletPool failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func UpdateCloudletPools(c *cli.Command, data []edgeproto.CloudletPool, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateCloudletPool %v\n", data[ii])
		myerr := UpdateCloudletPool(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowCloudletPoolCmd = &cli.Command{
	Use:          "ShowCloudletPool",
	OptionalArgs: strings.Join(append(CloudletPoolRequiredArgs, CloudletPoolOptionalArgs...), " "),
	AliasArgs:    strings.Join(CloudletPoolAliasArgs, " "),
	SpecialArgs:  &CloudletPoolSpecialArgs,
	Comments:     CloudletPoolComments,
	ReqData:      &edgeproto.CloudletPool{},
	ReplyData:    &edgeproto.CloudletPool{},
	Run:          runShowCloudletPool,
}

func runShowCloudletPool(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.CloudletPool)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowCloudletPool(c, obj)
}

func ShowCloudletPool(c *cli.Command, in *edgeproto.CloudletPool) error {
	if CloudletPoolApiCmd == nil {
		return fmt.Errorf("CloudletPoolApi client not initialized")
	}
	ctx := context.Background()
	stream, err := CloudletPoolApiCmd.ShowCloudletPool(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowCloudletPool failed: %s", errstr)
	}

	objs := make([]*edgeproto.CloudletPool, 0)
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
			return fmt.Errorf("ShowCloudletPool recv failed: %s", errstr)
		}
		CloudletPoolHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowCloudletPools(c *cli.Command, data []edgeproto.CloudletPool, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowCloudletPool %v\n", data[ii])
		myerr := ShowCloudletPool(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AddCloudletPoolMemberCmd = &cli.Command{
	Use:          "AddCloudletPoolMember",
	RequiredArgs: strings.Join(CloudletPoolMemberRequiredArgs, " "),
	OptionalArgs: strings.Join(CloudletPoolMemberOptionalArgs, " "),
	AliasArgs:    strings.Join(CloudletPoolMemberAliasArgs, " "),
	SpecialArgs:  &CloudletPoolMemberSpecialArgs,
	Comments:     CloudletPoolMemberComments,
	ReqData:      &edgeproto.CloudletPoolMember{},
	ReplyData:    &edgeproto.Result{},
	Run:          runAddCloudletPoolMember,
}

func runAddCloudletPoolMember(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.CloudletPoolMember)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return AddCloudletPoolMember(c, obj)
}

func AddCloudletPoolMember(c *cli.Command, in *edgeproto.CloudletPoolMember) error {
	if CloudletPoolApiCmd == nil {
		return fmt.Errorf("CloudletPoolApi client not initialized")
	}
	ctx := context.Background()
	obj, err := CloudletPoolApiCmd.AddCloudletPoolMember(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("AddCloudletPoolMember failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func AddCloudletPoolMembers(c *cli.Command, data []edgeproto.CloudletPoolMember, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("AddCloudletPoolMember %v\n", data[ii])
		myerr := AddCloudletPoolMember(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var RemoveCloudletPoolMemberCmd = &cli.Command{
	Use:          "RemoveCloudletPoolMember",
	RequiredArgs: strings.Join(CloudletPoolMemberRequiredArgs, " "),
	OptionalArgs: strings.Join(CloudletPoolMemberOptionalArgs, " "),
	AliasArgs:    strings.Join(CloudletPoolMemberAliasArgs, " "),
	SpecialArgs:  &CloudletPoolMemberSpecialArgs,
	Comments:     CloudletPoolMemberComments,
	ReqData:      &edgeproto.CloudletPoolMember{},
	ReplyData:    &edgeproto.Result{},
	Run:          runRemoveCloudletPoolMember,
}

func runRemoveCloudletPoolMember(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.CloudletPoolMember)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return RemoveCloudletPoolMember(c, obj)
}

func RemoveCloudletPoolMember(c *cli.Command, in *edgeproto.CloudletPoolMember) error {
	if CloudletPoolApiCmd == nil {
		return fmt.Errorf("CloudletPoolApi client not initialized")
	}
	ctx := context.Background()
	obj, err := CloudletPoolApiCmd.RemoveCloudletPoolMember(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("RemoveCloudletPoolMember failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func RemoveCloudletPoolMembers(c *cli.Command, data []edgeproto.CloudletPoolMember, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("RemoveCloudletPoolMember %v\n", data[ii])
		myerr := RemoveCloudletPoolMember(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var CloudletPoolApiCmds = []*cobra.Command{
	CreateCloudletPoolCmd.GenCmd(),
	DeleteCloudletPoolCmd.GenCmd(),
	UpdateCloudletPoolCmd.GenCmd(),
	ShowCloudletPoolCmd.GenCmd(),
	AddCloudletPoolMemberCmd.GenCmd(),
	RemoveCloudletPoolMemberCmd.GenCmd(),
}

var CloudletPoolKeyRequiredArgs = []string{}
var CloudletPoolKeyOptionalArgs = []string{
	"organization",
	"name",
}
var CloudletPoolKeyAliasArgs = []string{}
var CloudletPoolKeyComments = map[string]string{
	"organization": "Name of the organization this pool belongs to",
	"name":         "CloudletPool Name",
}
var CloudletPoolKeySpecialArgs = map[string]string{}
var CloudletPoolRequiredArgs = []string{
	"org",
	"name",
}
var CloudletPoolOptionalArgs = []string{
	"cloudlets",
}
var CloudletPoolAliasArgs = []string{
	"org=key.organization",
	"name=key.name",
}
var CloudletPoolComments = map[string]string{
	"fields":    "Fields are used for the Update API to specify which fields to apply",
	"org":       "Name of the organization this pool belongs to",
	"name":      "CloudletPool Name",
	"cloudlets": "Cloudlets part of the pool, specify cloudlets:empty=true to clear",
}
var CloudletPoolSpecialArgs = map[string]string{
	"cloudlets": "StringArray",
	"fields":    "StringArray",
}
var CloudletPoolMemberRequiredArgs = []string{
	"org",
	"pool",
}
var CloudletPoolMemberOptionalArgs = []string{
	"cloudlet",
}
var CloudletPoolMemberAliasArgs = []string{
	"org=key.organization",
	"pool=key.name",
	"cloudlet=cloudletname",
}
var CloudletPoolMemberComments = map[string]string{
	"org":      "Name of the organization this pool belongs to",
	"pool":     "CloudletPool Name",
	"cloudlet": "Cloudlet key",
}
var CloudletPoolMemberSpecialArgs = map[string]string{}
