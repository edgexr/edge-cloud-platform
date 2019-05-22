package ormctl

import (
	"encoding/json"
	fmt "fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/cli"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgecli "github.com/mobiledgex/edge-cloud/edgectl/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	webrtc "github.com/pion/webrtc/v2"
	"github.com/spf13/cobra"
)

// We don't use the auto-generated Command because the client
// must implement the webrtc protocol.

const runCommandRequiredArgs = "region command appname appvers developer clustername clusterdeveloper cloudlet operator"

var runCommandAliasArgs = []string{
	"appname=execrequest.appinstkey.appkey.name",
	"appvers=execrequest.appinstkey.appkey.version",
	"developer=execrequest.appinstkey.appkey.developerkey.name",
	"clustername=execrequest.appinstkey.clusterinstkey.clusterkey.name",
	"clusterdeveloper=execrequest.appinstkey.clusterinstkey.developer",
	"cloudlet=execrequest.appinstkey.clusterinstkey.cloudletkey.name",
	"operator=execrequest.appinstkey.clusterinstkey.cloudletkey.operatorkey.name",
	"command=execrequest.command",
}

func GetRunCommandCmd() *cobra.Command {
	cmd := genCmd(&Command{
		Use:          "RunCommand",
		RequiredArgs: runCommandRequiredArgs,
		Run:          runExecRequest,
	})
	return cmd
}

func runExecRequest(cmd *cobra.Command, args []string) error {
	input := cli.Input{
		RequiredArgs: strings.Split(runCommandRequiredArgs, " "),
		AliasArgs:    runCommandAliasArgs,
	}
	req := ormapi.RegionExecRequest{}
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
		err = check(st, err, nil)
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
