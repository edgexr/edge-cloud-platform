// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: restagtable.proto

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
var ResTagTableApiCmd edgeproto.ResTagTableApiClient

var CreateResTagTableCmd = &cli.Command{
	Use:          "CreateResTagTable",
	RequiredArgs: strings.Join(ResTagTableRequiredArgs, " "),
	OptionalArgs: strings.Join(ResTagTableOptionalArgs, " "),
	AliasArgs:    strings.Join(ResTagTableAliasArgs, " "),
	SpecialArgs:  &ResTagTableSpecialArgs,
	Comments:     ResTagTableComments,
	ReqData:      &edgeproto.ResTagTable{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateResTagTable,
}

func runCreateResTagTable(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTable)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateResTagTable(c, obj)
}

func CreateResTagTable(c *cli.Command, in *edgeproto.ResTagTable) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ResTagTableApiCmd.CreateResTagTable(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateResTagTable failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateResTagTables(c *cli.Command, data []edgeproto.ResTagTable, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateResTagTable %v\n", data[ii])
		myerr := CreateResTagTable(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteResTagTableCmd = &cli.Command{
	Use:          "DeleteResTagTable",
	RequiredArgs: strings.Join(ResTagTableRequiredArgs, " "),
	OptionalArgs: strings.Join(ResTagTableOptionalArgs, " "),
	AliasArgs:    strings.Join(ResTagTableAliasArgs, " "),
	SpecialArgs:  &ResTagTableSpecialArgs,
	Comments:     ResTagTableComments,
	ReqData:      &edgeproto.ResTagTable{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteResTagTable,
}

func runDeleteResTagTable(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTable)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteResTagTable(c, obj)
}

func DeleteResTagTable(c *cli.Command, in *edgeproto.ResTagTable) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ResTagTableApiCmd.DeleteResTagTable(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteResTagTable failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteResTagTables(c *cli.Command, data []edgeproto.ResTagTable, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteResTagTable %v\n", data[ii])
		myerr := DeleteResTagTable(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateResTagTableCmd = &cli.Command{
	Use:          "UpdateResTagTable",
	RequiredArgs: strings.Join(ResTagTableRequiredArgs, " "),
	OptionalArgs: strings.Join(ResTagTableOptionalArgs, " "),
	AliasArgs:    strings.Join(ResTagTableAliasArgs, " "),
	SpecialArgs:  &ResTagTableSpecialArgs,
	Comments:     ResTagTableComments,
	ReqData:      &edgeproto.ResTagTable{},
	ReplyData:    &edgeproto.Result{},
	Run:          runUpdateResTagTable,
}

func runUpdateResTagTable(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTable)
	jsonMap, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	obj.Fields = cli.GetSpecifiedFields(jsonMap, c.ReqData)
	return UpdateResTagTable(c, obj)
}

func UpdateResTagTable(c *cli.Command, in *edgeproto.ResTagTable) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ResTagTableApiCmd.UpdateResTagTable(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateResTagTable failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func UpdateResTagTables(c *cli.Command, data []edgeproto.ResTagTable, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateResTagTable %v\n", data[ii])
		myerr := UpdateResTagTable(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowResTagTableCmd = &cli.Command{
	Use:          "ShowResTagTable",
	OptionalArgs: strings.Join(append(ResTagTableRequiredArgs, ResTagTableOptionalArgs...), " "),
	AliasArgs:    strings.Join(ResTagTableAliasArgs, " "),
	SpecialArgs:  &ResTagTableSpecialArgs,
	Comments:     ResTagTableComments,
	ReqData:      &edgeproto.ResTagTable{},
	ReplyData:    &edgeproto.ResTagTable{},
	Run:          runShowResTagTable,
}

func runShowResTagTable(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTable)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowResTagTable(c, obj)
}

func ShowResTagTable(c *cli.Command, in *edgeproto.ResTagTable) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ResTagTableApiCmd.ShowResTagTable(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowResTagTable failed: %s", errstr)
	}

	objs := make([]*edgeproto.ResTagTable, 0)
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
			return fmt.Errorf("ShowResTagTable recv failed: %s", errstr)
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
func ShowResTagTables(c *cli.Command, data []edgeproto.ResTagTable, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowResTagTable %v\n", data[ii])
		myerr := ShowResTagTable(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AddResTagCmd = &cli.Command{
	Use:          "AddResTag",
	RequiredArgs: strings.Join(ResTagTableRequiredArgs, " "),
	OptionalArgs: strings.Join(ResTagTableOptionalArgs, " "),
	AliasArgs:    strings.Join(ResTagTableAliasArgs, " "),
	SpecialArgs:  &ResTagTableSpecialArgs,
	Comments:     ResTagTableComments,
	ReqData:      &edgeproto.ResTagTable{},
	ReplyData:    &edgeproto.Result{},
	Run:          runAddResTag,
}

func runAddResTag(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTable)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return AddResTag(c, obj)
}

func AddResTag(c *cli.Command, in *edgeproto.ResTagTable) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ResTagTableApiCmd.AddResTag(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("AddResTag failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func AddResTags(c *cli.Command, data []edgeproto.ResTagTable, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("AddResTag %v\n", data[ii])
		myerr := AddResTag(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var RemoveResTagCmd = &cli.Command{
	Use:          "RemoveResTag",
	RequiredArgs: strings.Join(ResTagTableRequiredArgs, " "),
	OptionalArgs: strings.Join(ResTagTableOptionalArgs, " "),
	AliasArgs:    strings.Join(ResTagTableAliasArgs, " "),
	SpecialArgs:  &ResTagTableSpecialArgs,
	Comments:     ResTagTableComments,
	ReqData:      &edgeproto.ResTagTable{},
	ReplyData:    &edgeproto.Result{},
	Run:          runRemoveResTag,
}

func runRemoveResTag(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTable)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return RemoveResTag(c, obj)
}

func RemoveResTag(c *cli.Command, in *edgeproto.ResTagTable) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ResTagTableApiCmd.RemoveResTag(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("RemoveResTag failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func RemoveResTags(c *cli.Command, data []edgeproto.ResTagTable, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("RemoveResTag %v\n", data[ii])
		myerr := RemoveResTag(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var GetResTagTableCmd = &cli.Command{
	Use:          "GetResTagTable",
	RequiredArgs: strings.Join(ResTagTableKeyRequiredArgs, " "),
	OptionalArgs: strings.Join(ResTagTableKeyOptionalArgs, " "),
	AliasArgs:    strings.Join(ResTagTableKeyAliasArgs, " "),
	SpecialArgs:  &ResTagTableKeySpecialArgs,
	Comments:     ResTagTableKeyComments,
	ReqData:      &edgeproto.ResTagTableKey{},
	ReplyData:    &edgeproto.ResTagTable{},
	Run:          runGetResTagTable,
}

func runGetResTagTable(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ResTagTableKey)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return GetResTagTable(c, obj)
}

func GetResTagTable(c *cli.Command, in *edgeproto.ResTagTableKey) error {
	if ResTagTableApiCmd == nil {
		return fmt.Errorf("ResTagTableApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ResTagTableApiCmd.GetResTagTable(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("GetResTagTable failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func GetResTagTables(c *cli.Command, data []edgeproto.ResTagTableKey, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("GetResTagTable %v\n", data[ii])
		myerr := GetResTagTable(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ResTagTableApiCmds = []*cobra.Command{
	CreateResTagTableCmd.GenCmd(),
	DeleteResTagTableCmd.GenCmd(),
	UpdateResTagTableCmd.GenCmd(),
	ShowResTagTableCmd.GenCmd(),
	AddResTagCmd.GenCmd(),
	RemoveResTagCmd.GenCmd(),
	GetResTagTableCmd.GenCmd(),
}

var ResTagTableKeyRequiredArgs = []string{}
var ResTagTableKeyOptionalArgs = []string{
	"name",
	"organization",
}
var ResTagTableKeyAliasArgs = []string{}
var ResTagTableKeyComments = map[string]string{
	"name":         "Resource Table Name",
	"organization": "Operator organization of the cloudlet site.",
}
var ResTagTableKeySpecialArgs = map[string]string{}
var ResTagTableRequiredArgs = []string{
	"res",
	"organization",
	"tags",
}
var ResTagTableOptionalArgs = []string{
	"azone",
}
var ResTagTableAliasArgs = []string{
	"res=key.name",
	"organization=key.organization",
}
var ResTagTableComments = map[string]string{
	"res":           "Resource Table Name",
	"organization":  "Operator organization of the cloudlet site.",
	"tags":          "One or more string tags, specify tags:empty=true to clear",
	"azone":         "Availability zone(s) of resource if required",
	"deleteprepare": "Preparing to be deleted",
}
var ResTagTableSpecialArgs = map[string]string{
	"fields": "StringArray",
	"tags":   "StringToString",
}
