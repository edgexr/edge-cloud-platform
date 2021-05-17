package mccli

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

var LookupKey = "lookupkey"

type setFieldsFunc func(in map[string]interface{})

func (s *RootCommand) runRest(path string, ops ...runRestOp) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		if c.ReplyData == nil {
			c.ReplyData = &ormapi.Result{}
		}
		c.CobraCmd.SilenceUsage = true

		in, err := c.ParseInput(args)
		if err != nil {
			if len(args) == 0 {
				// Force print usage since no args specified,
				// but obviously some are required.
				c.CobraCmd.SilenceUsage = false
			}
			return err
		}
		opts := runRestOptions{}
		opts.apply(ops)
		if opts.setFieldsFunc != nil {
			opts.setFieldsFunc(in)
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
		tok, err := ioutil.ReadFile(getTokenFile())
		if err == nil {
			s.token = strings.TrimSpace(string(tok))
		}
	}
	if s.skipVerify {
		s.client.SkipVerify = true
	}
	return nil
}

func getTokenFile() string {
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

type runRestOptions struct {
	setFieldsFunc func(in map[string]interface{})
}

type runRestOp func(opts *runRestOptions)

func withSetFieldsFunc(fn func(in map[string]interface{})) runRestOp {
	return func(opts *runRestOptions) { opts.setFieldsFunc = fn }
}

func (o *runRestOptions) apply(opts []runRestOp) {
	for _, opt := range opts {
		opt(o)
	}
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
	ops := []runRestOp{}
	if api.SetFieldsFunc != nil {
		ops = append(ops, withSetFieldsFunc(api.SetFieldsFunc))
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
		VerifyPassword:       api.VerifyPassword,
		StreamOut:            api.StreamOut,
		StreamOutIncremental: api.StreamOutIncremental,
		DataFlagOnly:         api.DataFlagOnly,
		Annotations:          annotations,
		Run:                  s.runRest(api.Path, ops...),
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
