package cliwrapper

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mccli"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

// These functions wrap around mcctl and implement ormclient.Api.
// This allows test code calling against ormclient.Api to use either
// direct REST API calls or go through the mcctl CLI.

type Client struct {
	DebugLog     bool
	SkipVerify   bool
	SilenceUsage bool
	rootCmd      *cobra.Command
	cliPaths     map[string][]string
}

func NewClient() *Client {
	s := &Client{}
	s.rootCmd = mccli.GetRootCommand()
	s.cliPaths = make(map[string][]string)
	s.addCliPaths(s.rootCmd, []string{})
	return s
}

func (s *Client) addCliPaths(cmd *cobra.Command, parent []string) {
	// In order for the wrapper to know what the organization
	// of the cobra commands are, we walk nested commands and build
	// a lookup map. This lets us find the path based on the api
	// command's name.
	for _, c := range cmd.Commands() {
		clipath := append(parent, c.Use)
		if name, ok := c.Annotations[mccli.LookupKey]; ok {
			fmt.Printf("added clipath %s -> %v\n", name, clipath)
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
	runData.RetStatus, runData.RetError = s.runObjs(runData.Uri, runData.Token, args, runData.In, runData.Out, ops...)
}

func (s *Client) runObjs(uri, token string, args []string, in, out interface{}, ops ...runOp) (int, error) {
	opts := runOptions{}
	opts.apply(ops)

	if str, ok := in.(string); ok {
		// json data
		m := make(map[string]interface{})
		err := json.Unmarshal([]byte(str), &m)
		if err != nil {
			return 0, err
		}
		ignore := make(map[string]struct{})
		objArgs := cli.MapToArgs([]string{}, m, ignore, nil, nil)
		args = append(args, objArgs...)
	} else {
		objArgs, err := cli.MarshalArgs(in, opts.ignore, nil)
		if err != nil {
			return 0, err
		}
		args = append(args, objArgs...)
	}
	if s.DebugLog {
		log.Printf("running mcctl %s\n", strings.Join(args, " "))
	}
	cmd := exec.Command("mcctl", args...)
	byt, err := cmd.CombinedOutput()
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
