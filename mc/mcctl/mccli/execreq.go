// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mccli

import (
	fmt "fmt"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cli"
	edgecli "github.com/edgexr/edge-cloud/edgectl/cli"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// We don't use the auto-generated Command because the client
// must use websocket connection

func (s *RootCommand) getExecCmd(name string, addFlagsFunc func(*pflag.FlagSet)) *cobra.Command {
	apiCmd := ormctl.MustGetCommand(name)
	cliCmd := s.ConvertCmd(apiCmd)
	cliCmd.Run = s.runExecRequest(apiCmd.Path)
	cliCmd.AddFlagsFunc = addFlagsFunc
	return cliCmd.GenCmd()
}

func (s *RootCommand) runExecRequest(path string) func(c *cli.Command, args []string) error {
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
		s.client.Debug = cli.Debug

		exchangeFunc := func() (*edgeproto.ExecRequest, error) {
			reply := edgeproto.ExecRequest{}
			st, err := s.client.PostJson(s.getUri()+path, s.token, &req, &reply)
			err = check(c, st, err, nil)
			if err != nil {
				return nil, err
			}

			if reply.Err != "" {
				return nil, fmt.Errorf("%s", reply.Err)
			}
			return &reply, nil
		}
		options := &edgecli.ExecOptions{
			Stdin: cli.Interactive,
			Tty:   cli.Tty,
		}
		return edgecli.RunEdgeTurn(&req.ExecRequest, options, exchangeFunc)
	}
}
