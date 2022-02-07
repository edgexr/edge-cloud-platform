// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

package gencmd

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud/cli"
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
func NodeKeyHideTags(in *edgeproto.NodeKey) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.Name = ""
	}
}

func NodeHideTags(in *edgeproto.Node) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.Key.Name = ""
	}
	if _, found := tags["nocmp"]; found {
		in.NotifyId = 0
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
		in.BuildDate = ""
	}
	if _, found := tags["nocmp"]; found {
		in.Hostname = ""
	}
}

func NodeDataHideTags(in *edgeproto.NodeData) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	for i0 := 0; i0 < len(in.Nodes); i0++ {
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].Key.Name = ""
		}
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].NotifyId = 0
		}
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].BuildMaster = ""
		}
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].BuildHead = ""
		}
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].BuildAuthor = ""
		}
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].BuildDate = ""
		}
		if _, found := tags["nocmp"]; found {
			in.Nodes[i0].Hostname = ""
		}
	}
}

var NodeApiCmd edgeproto.NodeApiClient

var ShowNodeCmd = &cli.Command{
	Use:          "ShowNode",
	OptionalArgs: strings.Join(append(NodeRequiredArgs, NodeOptionalArgs...), " "),
	AliasArgs:    strings.Join(NodeAliasArgs, " "),
	SpecialArgs:  &NodeSpecialArgs,
	Comments:     NodeComments,
	ReqData:      &edgeproto.Node{},
	ReplyData:    &edgeproto.Node{},
	Run:          runShowNode,
}

func runShowNode(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.Node)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowNode(c, obj)
}

func ShowNode(c *cli.Command, in *edgeproto.Node) error {
	if NodeApiCmd == nil {
		return fmt.Errorf("NodeApi client not initialized")
	}
	ctx := context.Background()
	stream, err := NodeApiCmd.ShowNode(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowNode failed: %s", errstr)
	}

	objs := make([]*edgeproto.Node, 0)
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
			return fmt.Errorf("ShowNode recv failed: %s", errstr)
		}
		NodeHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowNodes(c *cli.Command, data []edgeproto.Node, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowNode %v\n", data[ii])
		myerr := ShowNode(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var NodeApiCmds = []*cobra.Command{
	ShowNodeCmd.GenCmd(),
}

var NodeKeyRequiredArgs = []string{}
var NodeKeyOptionalArgs = []string{
	"name",
	"type",
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"region",
}
var NodeKeyAliasArgs = []string{}
var NodeKeyComments = map[string]string{
	"name":                              "Name or hostname of node",
	"type":                              "Node type",
	"cloudletkey.organization":          "Organization of the cloudlet site",
	"cloudletkey.name":                  "Name of the cloudlet",
	"cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"region":                            "Region the node is in",
}
var NodeKeySpecialArgs = map[string]string{}
var NodeRequiredArgs = []string{
	"name",
	"type",
	"cloudletorg",
	"cloudlet",
	"federatedorg",
	"region",
}
var NodeOptionalArgs = []string{
	"notifyid",
	"buildmaster",
	"buildhead",
	"buildauthor",
	"builddate",
	"hostname",
	"containerversion",
	"internalpki",
	"properties",
}
var NodeAliasArgs = []string{
	"name=key.name",
	"type=key.type",
	"cloudletorg=key.cloudletkey.organization",
	"cloudlet=key.cloudletkey.name",
	"federatedorg=key.cloudletkey.federatedorganization",
	"region=key.region",
}
var NodeComments = map[string]string{
	"fields":           "Fields are used for the Update API to specify which fields to apply",
	"name":             "Name or hostname of node",
	"type":             "Node type",
	"cloudletorg":      "Organization of the cloudlet site",
	"cloudlet":         "Name of the cloudlet",
	"federatedorg":     "Federated operator organization who shared this cloudlet",
	"region":           "Region the node is in",
	"notifyid":         "Id of client assigned by server (internal use only)",
	"buildmaster":      "Build Master Version",
	"buildhead":        "Build Head Version",
	"buildauthor":      "Build Author",
	"builddate":        "Build Date",
	"hostname":         "Hostname",
	"containerversion": "Docker edge-cloud container version which node instance use",
	"internalpki":      "Internal PKI Config",
	"properties":       "Additional properties",
}
var NodeSpecialArgs = map[string]string{
	"fields":     "StringArray",
	"properties": "StringToString",
}
var NodeDataRequiredArgs = []string{}
var NodeDataOptionalArgs = []string{
	"nodes:#.fields",
	"nodes:#.key.name",
	"nodes:#.key.type",
	"nodes:#.key.cloudletkey.organization",
	"nodes:#.key.cloudletkey.name",
	"nodes:#.key.cloudletkey.federatedorganization",
	"nodes:#.key.region",
	"nodes:#.notifyid",
	"nodes:#.buildmaster",
	"nodes:#.buildhead",
	"nodes:#.buildauthor",
	"nodes:#.builddate",
	"nodes:#.hostname",
	"nodes:#.containerversion",
	"nodes:#.internalpki",
	"nodes:#.properties",
}
var NodeDataAliasArgs = []string{}
var NodeDataComments = map[string]string{
	"nodes:#.fields":                                "Fields are used for the Update API to specify which fields to apply",
	"nodes:#.key.name":                              "Name or hostname of node",
	"nodes:#.key.type":                              "Node type",
	"nodes:#.key.cloudletkey.organization":          "Organization of the cloudlet site",
	"nodes:#.key.cloudletkey.name":                  "Name of the cloudlet",
	"nodes:#.key.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"nodes:#.key.region":                            "Region the node is in",
	"nodes:#.notifyid":                              "Id of client assigned by server (internal use only)",
	"nodes:#.buildmaster":                           "Build Master Version",
	"nodes:#.buildhead":                             "Build Head Version",
	"nodes:#.buildauthor":                           "Build Author",
	"nodes:#.builddate":                             "Build Date",
	"nodes:#.hostname":                              "Hostname",
	"nodes:#.containerversion":                      "Docker edge-cloud container version which node instance use",
	"nodes:#.internalpki":                           "Internal PKI Config",
	"nodes:#.properties":                            "Additional properties",
}
var NodeDataSpecialArgs = map[string]string{
	"nodes:#.fields":     "StringArray",
	"nodes:#.properties": "StringToString",
}
