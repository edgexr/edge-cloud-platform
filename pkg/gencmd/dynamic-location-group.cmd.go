// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: dynamic-location-group.proto

package gencmd

import (
	"context"
	fmt "fmt"
	distributed_match_engine "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/cli"
	proto "github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var DynamicLocGroupApiCmd distributed_match_engine.DynamicLocGroupApiClient

var SendToGroupCmd = &cli.Command{
	Use:          "SendToGroup",
	RequiredArgs: strings.Join(DlgMessageRequiredArgs, " "),
	OptionalArgs: strings.Join(DlgMessageOptionalArgs, " "),
	AliasArgs:    strings.Join(DlgMessageAliasArgs, " "),
	SpecialArgs:  &DlgMessageSpecialArgs,
	Comments:     DlgMessageComments,
	ReqData:      &distributed_match_engine.DlgMessage{},
	ReplyData:    &distributed_match_engine.DlgReply{},
	Run:          runSendToGroup,
}

func runSendToGroup(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*distributed_match_engine.DlgMessage)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return SendToGroup(c, obj)
}

func SendToGroup(c *cli.Command, in *distributed_match_engine.DlgMessage) error {
	if DynamicLocGroupApiCmd == nil {
		return fmt.Errorf("DynamicLocGroupApi client not initialized")
	}
	ctx := context.Background()
	obj, err := DynamicLocGroupApiCmd.SendToGroup(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("SendToGroup failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func SendToGroups(c *cli.Command, data []distributed_match_engine.DlgMessage, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("SendToGroup %v\n", data[ii])
		myerr := SendToGroup(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DynamicLocGroupApiCmds = []*cobra.Command{
	SendToGroupCmd.GenCmd(),
}

var DlgMessageRequiredArgs = []string{}
var DlgMessageOptionalArgs = []string{
	"ver",
	"lgid",
	"groupcookie",
	"messageid",
	"acktype",
	"message",
}
var DlgMessageAliasArgs = []string{}
var DlgMessageComments = map[string]string{
	"lgid":        "Dynamic Location Group Id",
	"groupcookie": "Group Cookie if secure",
	"messageid":   "Message ID",
	"acktype":     ", one of AckEachMessage, AsyEveryNMessage, NoAck",
	"message":     "Message",
}
var DlgMessageSpecialArgs = map[string]string{}
var DlgReplyRequiredArgs = []string{}
var DlgReplyOptionalArgs = []string{
	"ver",
	"ackid",
	"groupcookie",
}
var DlgReplyAliasArgs = []string{}
var DlgReplyComments = map[string]string{
	"ackid":       "AckId",
	"groupcookie": "Group Cookie for Secure comm",
}
var DlgReplySpecialArgs = map[string]string{}
