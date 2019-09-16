package ormctl

import (
	"encoding/json"
	fmt "fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	edgecli "github.com/mobiledgex/edge-cloud/edgectl/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	webrtc "github.com/pion/webrtc/v2"
	"github.com/spf13/cobra"
)

// We don't use the auto-generated Command because the client
// must implement the webrtc protocol.

const runCommandRequiredArgs = "region command appname appvers developer cluster cloudlet operator"
const runCommandOptionalArgs = "containerid"

var runCommandAliasArgs = []string{
	"appname=execrequest.appinstkey.appkey.name",
	"appvers=execrequest.appinstkey.appkey.version",
	"developer=execrequest.appinstkey.appkey.developerkey.name",
	"cluster=execrequest.appinstkey.clusterinstkey.clusterkey.name",
	"clusterdeveloper=execrequest.appinstkey.clusterinstkey.developer",
	"cloudlet=execrequest.appinstkey.clusterinstkey.cloudletkey.name",
	"operator=execrequest.appinstkey.clusterinstkey.cloudletkey.operatorkey.name",
	"command=execrequest.command",
	"containerid=execrequest.containerid",
}

func GetRunCommandCmd() *cobra.Command {
	RunCommandCmd.Run = runExecRequest
	RunCommandCmd.RequiredArgs = runCommandRequiredArgs
	RunCommandCmd.OptionalArgs = runCommandOptionalArgs
	return RunCommandCmd.GenCmd()
}

func runExecRequest(c *cli.Command, args []string) error {
	input := cli.Input{
		RequiredArgs: strings.Split(runCommandRequiredArgs, " "),
		AliasArgs:    runCommandAliasArgs,
	}
	req := ormapi.RegionExecRequest{}

	var developer string
	var clusterdeveloper string
	for _, arg := range args {
		parts := strings.Split(arg, "=")
		if parts[0] == "developer" {
			developer = parts[1]
		}
		if parts[1] == "clusterdeveloper" {
			clusterdeveloper = parts[1]
		}
	}
	if clusterdeveloper == "" && developer != "" {
		args = append(args, fmt.Sprintf("clusterdeveloper=%s", developer))
	}

	_, err := input.ParseArgs(args, &req)
	if err != nil {
		return err
	}

	exchangeFunc := func(offer webrtc.SessionDescription) (*webrtc.SessionDescription, error) {
		offerBytes, err := json.Marshal(&offer)
		if err != nil {
			return nil, err
		}
		req.ExecRequest.Offer = string(offerBytes)

		reply := edgeproto.ExecRequest{}
		st, err := client.PostJson(getUri()+"/auth/ctrl/RunCommand", Token, &req, &reply)
		err = check(c, st, err, nil)
		if err != nil {
			return nil, err
		}

		if reply.Err != "" {
			return nil, fmt.Errorf("%s", reply.Err)
		}
		if reply.Answer == "" {
			return nil, fmt.Errorf("empty answer")
		}

		answer := webrtc.SessionDescription{}
		err = json.Unmarshal([]byte(reply.Answer), &answer)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal answer %s, %v",
				reply.Answer, err)
		}
		return &answer, nil
	}
	return edgecli.RunWebrtcShell(exchangeFunc)
}
