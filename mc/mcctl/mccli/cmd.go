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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormclient"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/log"
	"github.com/spf13/cobra"
)

var LookupKey = "lookupkey"

func (s *RootCommand) runRest(path string) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		if c.ReplyData == nil {
			c.ReplyData = &ormapi.Result{}
		}
		c.CobraCmd.SilenceUsage = true

		if s.client.PrintTransformations {
			fmt.Printf("%s: transform args %v to data\n", log.GetLineno(0), args)
		}
		mapData, err := c.ParseInput(args)
		if err != nil {
			if len(args) == 0 {
				// Force print usage since no args specified,
				// but obviously some are required.
				c.CobraCmd.SilenceUsage = false
			}
			return err
		}
		in := mapData.Data
		if s.client.PrintTransformations {
			fmt.Printf("%s: transformed args to data %#v\n", log.GetLineno(0), in)
		}

		s.client.Debug = cli.Debug
		if c.StreamOut && c.StreamOutIncremental {
			// print streamed data as it comes
			replyReady := func() {
				check(c, 0, nil, c.ReplyData)
			}
			st, err := s.client.PostJsonStreamOut(s.getUri()+path,
				s.token, in, c.ReplyData, replyReady)
			return check(c, st, err, nil)
		} else if c.StreamOut {
			// gather streamed data into array to print
			outs := make([]interface{}, 0)
			replyReady := func() {
				// because c.ReplyData is a pointer, we
				// need to make a copy of the underlying
				// object before we can let the stream out
				// function write to it again.
				// Note that copy here is not a pointer,
				// it is the struct value.
				copy := reflect.Indirect(reflect.ValueOf(c.ReplyData)).Interface()
				outs = append(outs, copy)
			}
			st, err := s.client.PostJsonStreamOut(s.getUri()+path,
				s.token, in, c.ReplyData, replyReady)
			// print output
			check(c, st, nil, outs)
			return check(c, st, err, nil)
		} else {
			if s.clearState {
				ormclient.ClearObject(c.ReplyData)
			}
			st, err := s.client.PostJson(s.getUri()+path, s.token,
				in, c.ReplyData)
			return check(c, st, err, c.ReplyData)
		}
	}
}

func check(c *cli.Command, status int, err error, reply interface{}) error {
	wr := c.CobraCmd.OutOrStdout()
	// all failure cases result in error getting set (by PostJson)
	if err != nil {
		if status != 0 {
			return fmt.Errorf("%s (%d), %v", http.StatusText(status), status, err)
		}
		return err
	}
	// success
	if res, ok := reply.(*ormapi.Result); ok && !cli.Parsable {
		// pretty print result
		if res.Message != "" {
			fmt.Fprintln(wr, res.Message)
		}
		return nil
	}
	if res, ok := reply.(*ormapi.WSStreamPayload); ok && !cli.Parsable {
		if res.Data == nil {
			return nil
		}
		if out, ok := res.Data.(string); ok {
			fmt.Fprint(wr, out)
			return nil
		}
		reply = res.Data
	}
	if res, ok := reply.(*ormapi.UserResponse); ok && !cli.Parsable {
		if res.Message != "" {
			fmt.Fprintln(wr, res.Message)
			fmt.Fprintln(wr, res.TOTPSharedKey)
		}
		return nil
	}
	// formatted output
	if reply != nil {
		// don't write output for empty slices
		if reflect.TypeOf(reply).Kind() == reflect.Slice {
			if reflect.ValueOf(reply).Len() == 0 {
				return nil
			}
		}
		err = c.WriteOutput(wr, reply, cli.OutputFormat)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *RootCommand) PreRunE(cmd *cobra.Command, args []string) error {
	if s.token == "" {
		s.token = os.Getenv("TOKEN")
	}
	if s.token == "" {
		tok, err := ioutil.ReadFile(GetTokenFile())
		if err == nil {
			s.token = strings.TrimSpace(string(tok))
		}
	}
	if s.skipVerify {
		s.client.SkipVerify = true
	}
	return nil
}

func GetTokenFile() string {
	home := os.Getenv("HOME")
	return home + "/.mctoken"
}

func GetAdminFile() string {
	home := os.Getenv("HOME")
	return home + "/.mcctl_admin"
}

func (s *RootCommand) getUri() string {
	prefix := ""
	if !strings.HasPrefix(s.addr, "http") {
		prefix = "http://"
	}
	return prefix + s.addr + "/api/v1"
}

func (s *RootCommand) ConvertCmd(api *ormctl.ApiCommand) *cli.Command {
	use := api.Use
	if use == "" {
		// generate the same way we do for protobuf methods
		use = api.Name
		if api.ReqData != nil {
			typ := reflect.TypeOf(api.ReqData)
			if typ.Kind() == reflect.Ptr {
				typ = typ.Elem()
			}
			typeName := typ.Name()
			if use != typeName {
				use = strings.TrimSuffix(use, typeName)
			}
		}
		use = strings.ToLower(use)
	}
	annotations := map[string]string{
		LookupKey: api.Name,
	}
	cmd := &cli.Command{
		Use:                  use,
		Short:                api.Short,
		RequiredArgs:         api.RequiredArgs,
		OptionalArgs:         api.OptionalArgs,
		AliasArgs:            api.AliasArgs,
		SpecialArgs:          api.SpecialArgs,
		Comments:             api.Comments,
		ReqData:              api.ReqData,
		ReplyData:            api.ReplyData,
		PasswordArg:          api.PasswordArg,
		CurrentPasswordArg:   api.CurrentPasswordArg,
		VerifyPassword:       api.VerifyPassword,
		StreamOut:            api.StreamOut,
		StreamOutIncremental: api.StreamOutIncremental,
		DataFlagOnly:         api.DataFlagOnly,
		Annotations:          annotations,
		Run:                  s.runRest(api.Path),
	}
	return cmd
}

func (s *RootCommand) getCmd(name string) *cobra.Command {
	return s.ConvertCmd(ormctl.MustGetCommand(name)).GenCmd()
}

func (s *RootCommand) getCmdGroup(names ...string) *cobra.Command {
	cmds := []*cli.Command{}
	var mainGroup *ormctl.ApiGroup
	for _, name := range names {
		apiGroup := ormctl.MustGetGroup(name)
		if mainGroup == nil {
			mainGroup = apiGroup
		}
		for _, c := range apiGroup.Commands {
			cmds = append(cmds, s.ConvertCmd(c))
		}
	}
	return cli.GenGroup(strings.ToLower(mainGroup.Name), mainGroup.Desc, cmds)
}
