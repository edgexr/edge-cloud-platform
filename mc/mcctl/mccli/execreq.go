package mccli

import (
	fmt "fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	edgecli "github.com/mobiledgex/edge-cloud/edgectl/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/spf13/cobra"
)

// We don't use the auto-generated Command because the client
// must use websocket connection

func getExecCmd(name string) *cobra.Command {
	apiCmd := ormctl.MustGetCommand(name)
	cliCmd := ConvertCmd(apiCmd)
	cliCmd.Run = runExecRequest(apiCmd.Path)
	return cliCmd.GenCmd()
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

		exchangeFunc := func() (*edgeproto.ExecRequest, error) {
			reply := edgeproto.ExecRequest{}
			st, err := client.PostJson(getUri()+path, Token, &req, &reply)
			err = check(c, st, err, nil)
			if err != nil {
				return nil, err
			}

			if reply.Err != "" {
				return nil, fmt.Errorf("%s", reply.Err)
			}
			return &reply, nil
		}
		return edgecli.RunEdgeTurn(&req.ExecRequest, exchangeFunc)
	}
}
