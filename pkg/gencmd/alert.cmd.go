// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

package gencmd

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/cli"
	_ "github.com/edgexr/edge-cloud-platform/d-match-engine/dme-proto"
	distributed_match_engine "github.com/edgexr/edge-cloud-platform/d-match-engine/dme-proto"
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
func AlertHideTags(in *edgeproto.Alert) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["timestamp"]; found {
		in.ActiveAt = distributed_match_engine.Timestamp{}
	}
	if _, found := tags["nocmp"]; found {
		in.NotifyId = 0
	}
	if _, found := tags["nocmp"]; found {
		in.Controller = ""
	}
}

var AlertApiCmd edgeproto.AlertApiClient

var ShowAlertCmd = &cli.Command{
	Use:          "ShowAlert",
	OptionalArgs: strings.Join(append(AlertRequiredArgs, AlertOptionalArgs...), " "),
	AliasArgs:    strings.Join(AlertAliasArgs, " "),
	SpecialArgs:  &AlertSpecialArgs,
	Comments:     AlertComments,
	ReqData:      &edgeproto.Alert{},
	ReplyData:    &edgeproto.Alert{},
	Run:          runShowAlert,
}

func runShowAlert(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.Alert)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowAlert(c, obj)
}

func ShowAlert(c *cli.Command, in *edgeproto.Alert) error {
	if AlertApiCmd == nil {
		return fmt.Errorf("AlertApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AlertApiCmd.ShowAlert(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowAlert failed: %s", errstr)
	}

	objs := make([]*edgeproto.Alert, 0)
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
			return fmt.Errorf("ShowAlert recv failed: %s", errstr)
		}
		AlertHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowAlerts(c *cli.Command, data []edgeproto.Alert, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowAlert %v\n", data[ii])
		myerr := ShowAlert(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AlertApiCmds = []*cobra.Command{
	ShowAlertCmd.GenCmd(),
}

var AlertRequiredArgs = []string{}
var AlertOptionalArgs = []string{
	"labels",
	"annotations",
	"state",
	"activeat",
	"value",
	"notifyid",
	"controller",
}
var AlertAliasArgs = []string{}
var AlertComments = map[string]string{
	"labels":      "Labels uniquely define the alert",
	"annotations": "Annotations are extra information about the alert",
	"state":       "State of the alert",
	"activeat":    "When alert became active",
	"value":       "Any value associated with alert",
	"notifyid":    "Id of client assigned by server (internal use only)",
	"controller":  "Connected controller unique id",
}
var AlertSpecialArgs = map[string]string{
	"annotations": "StringToString",
	"labels":      "StringToString",
}