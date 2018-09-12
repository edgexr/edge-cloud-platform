// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

package gencmd

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
import "strconv"
import "github.com/spf13/cobra"
import "context"
import "os"
import "io"
import "text/tabwriter"
import "github.com/spf13/pflag"
import "errors"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var NodeApiCmd edgeproto.NodeApiClient
var NodeIn edgeproto.Node
var NodeFlagSet = pflag.NewFlagSet("Node", pflag.ExitOnError)
var NodeNoConfigFlagSet = pflag.NewFlagSet("NodeNoConfig", pflag.ExitOnError)
var NodeInKeyNodeType string
var NodeTypeStrings = []string{
	"NodeUnknown",
	"NodeDME",
	"NodeCRM",
}

func NodeKeySlicer(in *edgeproto.NodeKey) []string {
	s := make([]string, 0, 3)
	s = append(s, in.Name)
	s = append(s, edgeproto.NodeType_name[int32(in.NodeType)])
	s = append(s, in.CloudletKey.OperatorKey.Name)
	s = append(s, in.CloudletKey.Name)
	return s
}

func NodeKeyHeaderSlicer() []string {
	s := make([]string, 0, 3)
	s = append(s, "Name")
	s = append(s, "NodeType")
	s = append(s, "CloudletKey-OperatorKey-Name")
	s = append(s, "CloudletKey-Name")
	return s
}

func NodeKeyWriteOutputArray(objs []*edgeproto.NodeKey) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(NodeKeyHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(NodeKeySlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func NodeKeyWriteOutputOne(obj *edgeproto.NodeKey) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(NodeKeyHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(NodeKeySlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func NodeSlicer(in *edgeproto.Node) []string {
	s := make([]string, 0, 3)
	if in.Fields == nil {
		in.Fields = make([]string, 1)
	}
	s = append(s, in.Fields[0])
	s = append(s, in.Key.Name)
	s = append(s, edgeproto.NodeType_name[int32(in.Key.NodeType)])
	s = append(s, in.Key.CloudletKey.OperatorKey.Name)
	s = append(s, in.Key.CloudletKey.Name)
	s = append(s, strconv.FormatUint(uint64(in.NotifyId), 10))
	return s
}

func NodeHeaderSlicer() []string {
	s := make([]string, 0, 3)
	s = append(s, "Fields")
	s = append(s, "Key-Name")
	s = append(s, "Key-NodeType")
	s = append(s, "Key-CloudletKey-OperatorKey-Name")
	s = append(s, "Key-CloudletKey-Name")
	s = append(s, "NotifyId")
	return s
}

func NodeWriteOutputArray(objs []*edgeproto.Node) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(NodeHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(NodeSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func NodeWriteOutputOne(obj *edgeproto.Node) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(NodeHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(NodeSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func NodeHideTags(in *edgeproto.Node) {
	if cmdsup.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cmdsup.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.NotifyId = 0
	}
}

var ShowNodeLocalCmd = &cobra.Command{
	Use: "ShowNodeLocal",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if NodeApiCmd == nil {
			return fmt.Errorf("NodeApi client not initialized")
		}
		var err error
		err = parseNodeEnums()
		if err != nil {
			return fmt.Errorf("ShowNodeLocal failed: %s", err.Error())
		}
		ctx := context.Background()
		stream, err := NodeApiCmd.ShowNodeLocal(ctx, &NodeIn)
		if err != nil {
			return fmt.Errorf("ShowNodeLocal failed: %s", err.Error())
		}
		objs := make([]*edgeproto.Node, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("ShowNodeLocal recv failed: %s", err.Error())
			}
			NodeHideTags(obj)
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return nil
		}
		NodeWriteOutputArray(objs)
		return nil
	},
}

var ShowNodeCmd = &cobra.Command{
	Use: "ShowNode",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if NodeApiCmd == nil {
			return fmt.Errorf("NodeApi client not initialized")
		}
		var err error
		err = parseNodeEnums()
		if err != nil {
			return fmt.Errorf("ShowNode failed: %s", err.Error())
		}
		ctx := context.Background()
		stream, err := NodeApiCmd.ShowNode(ctx, &NodeIn)
		if err != nil {
			return fmt.Errorf("ShowNode failed: %s", err.Error())
		}
		objs := make([]*edgeproto.Node, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("ShowNode recv failed: %s", err.Error())
			}
			NodeHideTags(obj)
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return nil
		}
		NodeWriteOutputArray(objs)
		return nil
	},
}

var NodeApiCmds = []*cobra.Command{
	ShowNodeLocalCmd,
	ShowNodeCmd,
}

func init() {
	NodeFlagSet.StringVar(&NodeIn.Key.Name, "key-name", "", "Key.Name")
	NodeFlagSet.StringVar(&NodeInKeyNodeType, "key-nodetype", "", "one of [NodeUnknown NodeDME NodeCRM]")
	NodeFlagSet.StringVar(&NodeIn.Key.CloudletKey.OperatorKey.Name, "key-cloudletkey-operatorkey-name", "", "Key.CloudletKey.OperatorKey.Name")
	NodeFlagSet.StringVar(&NodeIn.Key.CloudletKey.Name, "key-cloudletkey-name", "", "Key.CloudletKey.Name")
	NodeFlagSet.Int64Var(&NodeIn.NotifyId, "notifyid", 0, "NotifyId")
	ShowNodeLocalCmd.Flags().AddFlagSet(NodeFlagSet)
	ShowNodeCmd.Flags().AddFlagSet(NodeFlagSet)
}

func NodeApiAllowNoConfig() {
	ShowNodeLocalCmd.Flags().AddFlagSet(NodeNoConfigFlagSet)
	ShowNodeCmd.Flags().AddFlagSet(NodeNoConfigFlagSet)
}

func NodeSetFields() {
	NodeIn.Fields = make([]string, 0)
	if NodeFlagSet.Lookup("key-name").Changed {
		NodeIn.Fields = append(NodeIn.Fields, "2.1")
	}
	if NodeFlagSet.Lookup("key-nodetype").Changed {
		NodeIn.Fields = append(NodeIn.Fields, "2.2")
	}
	if NodeFlagSet.Lookup("key-cloudletkey-operatorkey-name").Changed {
		NodeIn.Fields = append(NodeIn.Fields, "2.3.1.1")
	}
	if NodeFlagSet.Lookup("key-cloudletkey-name").Changed {
		NodeIn.Fields = append(NodeIn.Fields, "2.3.2")
	}
	if NodeFlagSet.Lookup("notifyid").Changed {
		NodeIn.Fields = append(NodeIn.Fields, "3")
	}
}

func parseNodeEnums() error {
	if NodeInKeyNodeType != "" {
		switch NodeInKeyNodeType {
		case "NodeUnknown":
			NodeIn.Key.NodeType = edgeproto.NodeType(0)
		case "NodeDME":
			NodeIn.Key.NodeType = edgeproto.NodeType(1)
		case "NodeCRM":
			NodeIn.Key.NodeType = edgeproto.NodeType(2)
		default:
			return errors.New("Invalid value for NodeInKeyNodeType")
		}
	}
	return nil
}
