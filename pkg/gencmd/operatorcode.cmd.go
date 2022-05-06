// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: operatorcode.proto

package gencmd

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/cli"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
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
var OperatorCodeApiCmd edgeproto.OperatorCodeApiClient

var CreateOperatorCodeCmd = &cli.Command{
	Use:          "CreateOperatorCode",
	RequiredArgs: strings.Join(OperatorCodeRequiredArgs, " "),
	OptionalArgs: strings.Join(OperatorCodeOptionalArgs, " "),
	AliasArgs:    strings.Join(OperatorCodeAliasArgs, " "),
	SpecialArgs:  &OperatorCodeSpecialArgs,
	Comments:     OperatorCodeComments,
	ReqData:      &edgeproto.OperatorCode{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateOperatorCode,
}

func runCreateOperatorCode(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.OperatorCode)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateOperatorCode(c, obj)
}

func CreateOperatorCode(c *cli.Command, in *edgeproto.OperatorCode) error {
	if OperatorCodeApiCmd == nil {
		return fmt.Errorf("OperatorCodeApi client not initialized")
	}
	ctx := context.Background()
	obj, err := OperatorCodeApiCmd.CreateOperatorCode(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateOperatorCode failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateOperatorCodes(c *cli.Command, data []edgeproto.OperatorCode, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateOperatorCode %v\n", data[ii])
		myerr := CreateOperatorCode(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteOperatorCodeCmd = &cli.Command{
	Use:          "DeleteOperatorCode",
	RequiredArgs: strings.Join(OperatorCodeRequiredArgs, " "),
	OptionalArgs: strings.Join(OperatorCodeOptionalArgs, " "),
	AliasArgs:    strings.Join(OperatorCodeAliasArgs, " "),
	SpecialArgs:  &OperatorCodeSpecialArgs,
	Comments:     OperatorCodeComments,
	ReqData:      &edgeproto.OperatorCode{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteOperatorCode,
}

func runDeleteOperatorCode(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.OperatorCode)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteOperatorCode(c, obj)
}

func DeleteOperatorCode(c *cli.Command, in *edgeproto.OperatorCode) error {
	if OperatorCodeApiCmd == nil {
		return fmt.Errorf("OperatorCodeApi client not initialized")
	}
	ctx := context.Background()
	obj, err := OperatorCodeApiCmd.DeleteOperatorCode(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteOperatorCode failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteOperatorCodes(c *cli.Command, data []edgeproto.OperatorCode, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteOperatorCode %v\n", data[ii])
		myerr := DeleteOperatorCode(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowOperatorCodeCmd = &cli.Command{
	Use:          "ShowOperatorCode",
	OptionalArgs: strings.Join(append(OperatorCodeRequiredArgs, OperatorCodeOptionalArgs...), " "),
	AliasArgs:    strings.Join(OperatorCodeAliasArgs, " "),
	SpecialArgs:  &OperatorCodeSpecialArgs,
	Comments:     OperatorCodeComments,
	ReqData:      &edgeproto.OperatorCode{},
	ReplyData:    &edgeproto.OperatorCode{},
	Run:          runShowOperatorCode,
}

func runShowOperatorCode(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.OperatorCode)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowOperatorCode(c, obj)
}

func ShowOperatorCode(c *cli.Command, in *edgeproto.OperatorCode) error {
	if OperatorCodeApiCmd == nil {
		return fmt.Errorf("OperatorCodeApi client not initialized")
	}
	ctx := context.Background()
	stream, err := OperatorCodeApiCmd.ShowOperatorCode(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowOperatorCode failed: %s", errstr)
	}

	objs := make([]*edgeproto.OperatorCode, 0)
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
			return fmt.Errorf("ShowOperatorCode recv failed: %s", errstr)
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
func ShowOperatorCodes(c *cli.Command, data []edgeproto.OperatorCode, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowOperatorCode %v\n", data[ii])
		myerr := ShowOperatorCode(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var OperatorCodeApiCmds = []*cobra.Command{
	CreateOperatorCodeCmd.GenCmd(),
	DeleteOperatorCodeCmd.GenCmd(),
	ShowOperatorCodeCmd.GenCmd(),
}

var OperatorCodeRequiredArgs = []string{}
var OperatorCodeOptionalArgs = []string{
	"code",
	"organization",
}
var OperatorCodeAliasArgs = []string{}
var OperatorCodeComments = map[string]string{
	"code":         "MCC plus MNC code, or custom carrier code designation.",
	"organization": "Operator Organization name",
}
var OperatorCodeSpecialArgs = map[string]string{}