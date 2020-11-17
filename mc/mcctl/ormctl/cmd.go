package ormctl

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

var Addr string
var Token string
var SkipVerify bool
var client ormclient.Client

type setFieldsFunc func(in map[string]interface{})

func runRest(path string, ops ...runRestOp) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		if c.ReplyData == nil {
			c.ReplyData = &ormapi.Result{}
		}
		if cli.SilenceUsage {
			c.CobraCmd.SilenceUsage = true
		}

		in, err := c.ParseInput(args)
		if err != nil {
			return err
		}
		opts := runRestOptions{}
		opts.apply(ops)
		if opts.setFieldsFunc != nil {
			opts.setFieldsFunc(in)
		}

		client.Debug = cli.Debug
		if c.StreamOut && c.StreamOutIncremental {
			// print streamed data as it comes
			replyReady := func() {
				check(c, 0, nil, c.ReplyData)
			}
			st, err := client.PostJsonStreamOut(getUri()+path,
				Token, in, c.ReplyData, replyReady)
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
			st, err := client.PostJsonStreamOut(getUri()+path,
				Token, in, c.ReplyData, replyReady)
			// print output
			check(c, st, nil, outs)
			return check(c, st, err, nil)
		} else {
			st, err := client.PostJson(getUri()+path, Token,
				in, c.ReplyData)
			return check(c, st, err, c.ReplyData)
		}
	}
}

func check(c *cli.Command, status int, err error, reply interface{}) error {
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
			fmt.Println(res.Message)
		}
		return nil
	}
	if res, ok := reply.(*ormapi.WSStreamPayload); ok && !cli.Parsable {
		if res.Data == nil {
			return nil
		}
		if out, ok := res.Data.(string); ok {
			fmt.Print(out)
			return nil
		}
		reply = res.Data
	}
	if res, ok := reply.(*ormapi.UserResponse); ok && !cli.Parsable {
		if res.Message != "" {
			fmt.Println(res.Message)
			fmt.Println(res.TOTPSharedKey)
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
		err = c.WriteOutput(reply, cli.OutputFormat)
		if err != nil {
			return err
		}
	}
	return nil
}

func PreRunE(cmd *cobra.Command, args []string) error {
	if Token == "" {
		Token = os.Getenv("TOKEN")
	}
	if Token == "" {
		tok, err := ioutil.ReadFile(getTokenFile())
		if err == nil {
			Token = strings.TrimSpace(string(tok))
		}
	}
	if SkipVerify {
		client.SkipVerify = true
	}
	return nil
}

func getTokenFile() string {
	home := os.Getenv("HOME")
	return home + "/.mctoken"
}

func getUri() string {
	if !strings.HasPrefix(Addr, "http") {
		Addr = "http://" + Addr
	}
	return Addr + "/api/v1"
}

func getWSUri() string {
	newAddr := Addr
	if !strings.HasPrefix(Addr, "http") {
		newAddr = "http://" + Addr
	}
	newAddr = strings.Replace(Addr, "http", "ws", -1)
	return newAddr + "/ws/api/v1"
}

func addRegionComment(comments map[string]string) map[string]string {
	comments["region"] = "Region name"
	return comments
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
