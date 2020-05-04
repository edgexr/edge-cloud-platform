package ormctl

import (
	"bufio"
	"encoding/json"
	fmt "fmt"
	"os"
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

func GetRunCommandCmd() *cobra.Command {
	RunCommandCmd.Run = runExecRequest("/auth/ctrl/RunCommand")
	return RunCommandCmd.GenCmd()
}

func GetRunConsoleCmd() *cobra.Command {
	RunConsoleCmd.Run = runExecRequest("/auth/ctrl/RunConsole")
	return RunConsoleCmd.GenCmd()
}

func GetShowLogsCmd() *cobra.Command {
	ShowLogsCmd.Run = runExecRequest("/auth/ctrl/ShowLogs")
	return ShowLogsCmd.GenCmd()
}

func GetAccessCloudletCmd() *cobra.Command {
	AccessCloudletCmd.Run = runExecRequest("/auth/ctrl/AccessCloudlet")
	return AccessCloudletCmd.GenCmd()
}

func runExecRequest(path string) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		input := cli.Input{
			RequiredArgs: strings.Split(c.RequiredArgs, " "),
			AliasArgs:    strings.Split(c.AliasArgs, " "),
		}
		req := ormapi.RegionExecRequest{}
		_, err := input.ParseArgs(args, &req)
		if err != nil {
			return err
		}
		client.Debug = cli.Debug

		if client.McProxy {
			out := ormapi.WSStreamPayload{}
			reader := bufio.NewReader(os.Stdin)
			// print streamed data as it comes
			st, err := client.HandleWebsocketStreamOut(getWSUri()+path, Token, reader, &req, &out, func() {
				check(c, 0, nil, &out)
			})
			return check(c, st, err, nil)
		}

		exchangeFunc := func(offer *webrtc.SessionDescription) (*edgeproto.ExecRequest, *webrtc.SessionDescription, error) {
			if offer != nil {
				offerBytes, err := json.Marshal(offer)
				if err != nil {
					return nil, nil, err
				}
				req.ExecRequest.Offer = string(offerBytes)
			}

			reply := edgeproto.ExecRequest{}
			st, err := client.PostJson(getUri()+path, Token, &req, &reply)
			err = check(c, st, err, nil)
			if err != nil {
				return nil, nil, err
			}

			if reply.Err != "" {
				return nil, nil, fmt.Errorf("%s", reply.Err)
			}
			if offer != nil {
				if reply.Answer == "" {
					return nil, nil, fmt.Errorf("empty answer")
				}

				answer := webrtc.SessionDescription{}
				err = json.Unmarshal([]byte(reply.Answer), &answer)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to unmarshal answer %s, %v",
						reply.Answer, err)
				}
				return &reply, &answer, nil
			}
			return &reply, nil, nil
		}
		if req.ExecRequest.Webrtc {
			return edgecli.RunWebrtc(&req.ExecRequest, exchangeFunc, nil, edgecli.SetupLocalConsoleTunnel)
		}
		return edgecli.RunEdgeTurn(&req.ExecRequest, exchangeFunc, nil)
	}
}
