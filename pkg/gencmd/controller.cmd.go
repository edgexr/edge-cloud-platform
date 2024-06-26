// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: controller.proto

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
func ControllerHideTags(in *edgeproto.Controller) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.BuildMaster = ""
	}
	if _, found := tags["nocmp"]; found {
		in.BuildHead = ""
	}
	if _, found := tags["nocmp"]; found {
		in.BuildAuthor = ""
	}
	if _, found := tags["nocmp"]; found {
		in.Hostname = ""
	}
}

var ControllerApiCmd edgeproto.ControllerApiClient

var ShowControllerCmd = &cli.Command{
	Use:          "ShowController",
	OptionalArgs: strings.Join(append(ControllerRequiredArgs, ControllerOptionalArgs...), " "),
	AliasArgs:    strings.Join(ControllerAliasArgs, " "),
	SpecialArgs:  &ControllerSpecialArgs,
	Comments:     ControllerComments,
	ReqData:      &edgeproto.Controller{},
	ReplyData:    &edgeproto.Controller{},
	Run:          runShowController,
}

func runShowController(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.Controller)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowController(c, obj)
}

func ShowController(c *cli.Command, in *edgeproto.Controller) error {
	if ControllerApiCmd == nil {
		return fmt.Errorf("ControllerApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ControllerApiCmd.ShowController(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowController failed: %s", errstr)
	}

	objs := make([]*edgeproto.Controller, 0)
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
			return fmt.Errorf("ShowController recv failed: %s", errstr)
		}
		ControllerHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowControllers(c *cli.Command, data []edgeproto.Controller, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowController %v\n", data[ii])
		myerr := ShowController(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ControllerApiCmds = []*cobra.Command{
	ShowControllerCmd.GenCmd(),
}

var ControllerKeyRequiredArgs = []string{}
var ControllerKeyOptionalArgs = []string{
	"addr",
}
var ControllerKeyAliasArgs = []string{}
var ControllerKeyComments = map[string]string{
	"addr": "external API address",
}
var ControllerKeySpecialArgs = map[string]string{}
var ControllerRequiredArgs = []string{
	"key.addr",
}
var ControllerOptionalArgs = []string{
	"buildmaster",
	"buildhead",
	"buildauthor",
	"hostname",
}
var ControllerAliasArgs = []string{}
var ControllerComments = map[string]string{
	"fields":      "Fields are used for the Update API to specify which fields to apply",
	"key.addr":    "external API address",
	"buildmaster": "Build Master Version",
	"buildhead":   "Build Head Version",
	"buildauthor": "Build Author",
	"hostname":    "Hostname",
}
var ControllerSpecialArgs = map[string]string{
	"fields": "StringArray",
}
