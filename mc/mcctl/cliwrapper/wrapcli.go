package cliwrapper

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/cli"
)

// These functions wrap around mcctl and implement ormclient.Api.
// This allows test code calling against ormclient.Api to use either
// direct REST API calls or go through the mcctl CLI.

type Client struct {
	DebugLog   bool
	SkipVerify bool
}

func (s *Client) run(uri, token string, args []string) ([]byte, error) {
	uri = strings.TrimSuffix(uri, "/api/v1")
	args = append([]string{"--parsable", "--output-format", "json-compact",
		"--addr", uri}, args...)
	if token != "" {
		args = append([]string{"--token", token}, args...)
	}
	if s.SkipVerify {
		args = append([]string{"--skipverify"}, args...)
	}
	if s.DebugLog {
		log.Printf("running mcctl %s\n", strings.Join(args, " "))
	}
	cmd := exec.Command("mcctl", args...)
	return cmd.CombinedOutput()
}

func (s *Client) runObjs(uri, token string, args []string, in, out interface{}, ops ...runOp) (int, error) {
	opts := runOptions{}
	opts.apply(ops)

	objArgs, err := cli.MarshalArgs(in, opts.ignore)
	if err != nil {
		return 0, err
	}
	args = append(args, objArgs...)

	byt, err := s.run(uri, token, args)
	// note we lose the status code, since a non-StatusOK result
	// always generates an error.
	if err != nil {
		return 0, fmt.Errorf("%s, %v", string(byt), err)
	}
	str := strings.TrimSpace(string(byt))
	if out != nil && len(str) > 0 {
		if opts.streamOutIncremental {
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
