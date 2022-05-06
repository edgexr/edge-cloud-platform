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

package cliwrapper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mccli"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud/cli"
	edgelog "github.com/edgexr/edge-cloud/log"
	"github.com/spf13/cobra"
)

// These functions wrap around mcctl and implement ormclient.Api.
// This allows test code calling against ormclient.Api to use either
// direct REST API calls or go through the mcctl CLI.

type Client struct {
	DebugLog             bool
	SkipVerify           bool
	SilenceUsage         bool
	RunInline            bool
	InjectRequiredArgs   bool
	rootCmd              *mccli.RootCommand
	cliPaths             map[string][]string
	PrintTransformations bool
}

func NewClient() *Client {
	s := &Client{}
	s.rootCmd = mccli.GetRootCommand()
	s.cliPaths = make(map[string][]string)
	s.addCliPaths(s.rootCmd.CobraCmd, []string{})
	return s
}

func (s *Client) ForceDefaultTransport(enable bool) {
	s.rootCmd.ForceDefaultTransport(enable)
}

func (s *Client) EnablePrintTransformations() {
	s.PrintTransformations = true
	s.rootCmd.EnablePrintTransformations()
}

func (s *Client) addCliPaths(cmd *cobra.Command, parent []string) {
	// In order for the wrapper to know what the organization
	// of the cobra commands are, we walk nested commands and build
	// a lookup map. This lets us find the path based on the api
	// command's name.
	for _, c := range cmd.Commands() {
		clipath := append(parent, c.Use)
		if name, ok := c.Annotations[mccli.LookupKey]; ok {
			s.cliPaths[name] = clipath
		}
		s.addCliPaths(c, clipath)
	}
}

func (s *Client) Run(apiCmd *ormctl.ApiCommand, runData *mctestclient.RunData) {
	args := []string{}
	uri := strings.TrimSuffix(runData.Uri, "/api/v1")
	args = append(args, "--parsable", "--output-format", "json-compact",
		"--addr", uri)
	if runData.Token != "" {
		args = append(args, "--token", runData.Token)
	}
	if s.SkipVerify {
		args = append(args, "--skipverify")
	}
	if s.SilenceUsage {
		args = append(args, "--silence-usage")
	}
	clipath, found := s.cliPaths[apiCmd.Name]
	if !found {
		panic(fmt.Errorf("No clipath found for api command %s", apiCmd.Name))
	}
	args = append(args, clipath...)

	ops := []runOp{}
	if apiCmd.NoConfig != "" {
		ops = append(ops, withIgnore(strings.Split(apiCmd.NoConfig, ",")))
	}
	if apiCmd.StreamOutIncremental {
		ops = append(ops, withStreamOutIncremental())
	}
	runData.RetStatus, runData.RetError = s.runObjs(runData.Uri, runData.Token, args, runData.In, runData.Out, apiCmd, ops...)
}

func (s *Client) runObjs(uri, token string, args []string, in, out interface{}, apiCmd *ormctl.ApiCommand, ops ...runOp) (int, error) {
	opts := runOptions{}
	opts.apply(ops)

	if str, ok := in.(string); ok {
		// json data
		args = append(args, "--data", str)
	} else {
		if s.PrintTransformations {
			fmt.Printf("%s: transforming input %#v to args\n", edgelog.GetLineno(0), in)
		}
		objArgs, err := cli.MarshalArgs(in, opts.ignore, strings.Fields(apiCmd.AliasArgs))
		if err != nil {
			return 0, err
		}
		if s.PrintTransformations {
			fmt.Printf("%s: transformed to args %v\n", edgelog.GetLineno(0), objArgs)
		}
		args = append(args, objArgs...)
	}
	if s.InjectRequiredArgs {
		args = injectRequiredArgs(args, apiCmd)
	}
	if s.DebugLog {
		log.Printf("running mcctl %s\n", strings.Join(args, " "))
	}
	// Running inline avoids spawning a process, and it also
	// allows unit-test to include the mcctl code when calculating
	// test code coverage. Inline should be used for unit-tests,
	// exec process should be used for e2e-tests.
	var byt []byte
	var err error
	if s.RunInline {
		s.rootCmd.ClearState()
		s.rootCmd.CobraCmd.SetArgs(args)
		buf := bytes.Buffer{}
		s.rootCmd.CobraCmd.SetOutput(&buf)
		err = s.rootCmd.CobraCmd.Execute()
		if err != nil {
			// error should contain the full error, such as
			// "status (int), error msg"
			buf = bytes.Buffer{}
			buf.WriteString(err.Error())
		}
		byt = buf.Bytes()
	} else {
		cmd := exec.Command("mcctl", args...)
		byt, err = cmd.CombinedOutput()
	}
	// note we lose the status code, since a non-StatusOK result
	// always generates an error.
	if err != nil {
		status := 0
		out := string(byt)
		if out != "" {
			// special case for Forbidden for e2e tests
			lines := strings.Split(out, "\n")
			if strings.Contains(lines[0], "code=403, message=Forbidden") {
				status = http.StatusForbidden
			}
		}
		// ignore err, it's always something like "exit status 1"
		// format of output should be "status (int), error msg"
		outParts := strings.SplitN(out, ", ", 2)
		if len(outParts) == 2 {
			re := regexp.MustCompile(`^.+\((\d+)\)$`)
			matched := re.FindStringSubmatch(outParts[0])
			if len(matched) == 2 {
				st, err := strconv.Atoi(string(matched[1]))
				if err == nil {
					out = strings.TrimSpace(outParts[1])
					return st, errors.New(out)
				}
			}
		}
		return status, errors.New(out)
	}
	str := strings.TrimSpace(string(byt))
	if out != nil && len(str) > 0 {
		if strp, ok := out.(*string); ok {
			*strp = str
		} else if opts.streamOutIncremental {
			// each line is a separate object, join together in a json array
			lines := strings.Split(str, "\n")
			arr := "[" + strings.Join(lines, ",") + "]"
			err = json.Unmarshal([]byte(arr), out)
		} else {
			err = json.Unmarshal([]byte(str), out)
		}
		if err != nil {
			return 0, fmt.Errorf("error %v unmarshalling: %s\n", err, string(byt))
		}
	}
	return http.StatusOK, nil
}

// InjectRequiredArgs ensures that all required args are present.
// This covers two cases, one in unit-tests where not all args are supplied
// (like for creating Apps against a dummy controller), or for required
// args that should be an empty value, but marshaling ignores and drops them
// (like empty org for admin role for AddUserRole).
func injectRequiredArgs(args []string, apiCmd *ormctl.ApiCommand) []string {
	if apiCmd.ReqData == nil || len(apiCmd.RequiredArgs) == 0 {
		return args
	}
	// get args already specified
	specifiedArgs := map[string]struct{}{}
	for _, arg := range args {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			continue
		}
		specifiedArgs[kv[0]] = struct{}{}
	}
	// build unalias map
	unalias := make(map[string]string)
	for _, alias := range strings.Fields(apiCmd.AliasArgs) {
		kv := strings.SplitN(alias, "=", 2)
		if len(kv) != 2 {
			continue
		}
		unalias[kv[0]] = kv[1]
	}
	inType := reflect.TypeOf(apiCmd.ReqData)
	if inType.Kind() == reflect.Ptr {
		inType = inType.Elem()
	}
	for _, req := range strings.Fields(apiCmd.RequiredArgs) {
		if _, found := specifiedArgs[req]; found {
			// already present
			continue
		}
		// To figure out what value to specify, we need to
		// find the field in the input struct.
		// First unalias the arg name, so we get the hierarchical
		// struct name.
		hierName := req
		if hn, ok := unalias[req]; ok {
			hierName = hn
		}
		field, found := cli.FindHierField(inType, hierName, cli.ArgsNamespace)
		if !found {
			continue
		}
		if field.Type.Kind() == reflect.String {
			args = append(args, fmt.Sprintf(`%s=""`, req))
		} else if field.Type.Kind() == reflect.Map {
			args = append(args, fmt.Sprintf("%s=k=v", req))
		} else {
			zero := reflect.Zero(field.Type)
			args = append(args, fmt.Sprintf("%s=%v", req, zero))
		}
	}
	return args
}

type runOptions struct {
	ignore               []string
	streamOutIncremental bool
}

type runOp func(opts *runOptions)

func withIgnore(ignore []string) runOp {
	return func(opts *runOptions) { opts.ignore = ignore }
}

func withStreamOutIncremental() runOp {
	return func(opts *runOptions) { opts.streamOutIncremental = true }
}

func (o *runOptions) apply(ops []runOp) {
	for _, op := range ops {
		op(o)
	}
}
