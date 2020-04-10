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

	"github.com/mobiledgex/edge-cloud/cli"
)

// These functions wrap around mcctl and implement ormclient.Api.
// This allows test code calling against ormclient.Api to use either
// direct REST API calls or go through the mcctl CLI.

type Client struct {
	DebugLog     bool
	SkipVerify   bool
	SilenceUsage bool
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
	if s.SilenceUsage {
		args = append([]string{"--silence-usage"}, args...)
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
	byt, err := s.run(uri, token, args)
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
