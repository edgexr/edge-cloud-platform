package ormctl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/cli"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	yaml "github.com/mobiledgex/yaml/v2"
	"github.com/spf13/cobra"
)

var Addr string
var Token string
var Parsable bool
var Data string
var Datafile string
var OutputFormat string
var SkipVerify bool
var Debug bool
var client ormclient.Client

type Command struct {
	Use                  string
	RequiredArgs         string
	OptionalArgs         string
	AliasArgs            string
	ReqData              interface{}
	ReplyData            interface{}
	Path                 string
	PasswordArg          string
	VerifyPassword       bool
	DataFlagOnly         bool
	StreamOut            bool
	StreamOutIncremental bool
	SendObj              bool
	Run                  func(cmd *cobra.Command, args []string) error
}

func genCmd(c *Command) *cobra.Command {
	short := c.Use
	args := usageArgs(c.RequiredArgs)
	if len(args) > 0 {
		short += " " + strings.Join(args, " ")
	}
	args = usageArgs(c.OptionalArgs)
	if len(args) > 0 {
		short += " [" + strings.Join(args, " ") + "]"
	}
	if len(short) > 60 {
		short = short[:57] + "..."
	}
	if c.ReplyData == nil {
		c.ReplyData = &ormapi.Result{}
	}
	if c.Run == nil {
		c.Run = runE(c)
	}

	cmd := &cobra.Command{
		Use:   c.Use,
		Short: short,
		Long:  longHelp(short, c),
		RunE:  c.Run,
	}
	return cmd
}

func usageArgs(str string) []string {
	args := strings.Fields(str)
	for ii, _ := range args {
		args[ii] = args[ii] + "="
	}
	return args
}

func runE(c *Command) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		var in interface{}
		if Datafile != "" {
			byt, err := ioutil.ReadFile(Datafile)
			if err != nil {
				return err
			}
			Data = string(byt)
		}
		if Data != "" {
			in = make(map[string]interface{})
			err := json.Unmarshal([]byte(Data), &in)
			if err != nil {
				// try yaml
				// we need to use the actual reqData object
				// since postJson will try to convert to json,
				// so effectively we need to convert from
				// yaml tags to json tags via the object.
				in = c.ReqData
				err2 := yaml.Unmarshal([]byte(Data), in)
				if err2 != nil {
					return fmt.Errorf("unable to unmarshal json or yaml data, %v, %v", err, err2)
				}
			}
		} else {
			if c.DataFlagOnly {
				return fmt.Errorf("--data must be used to supply json/yaml-formatted input data")
			}
			input := cli.Input{
				RequiredArgs:   strings.Fields(c.RequiredArgs),
				AliasArgs:      strings.Fields(c.AliasArgs),
				PasswordArg:    c.PasswordArg,
				VerifyPassword: c.VerifyPassword,
				DecodeHook:     edgeproto.EnumDecodeHook,
			}
			argsMap, err := input.ParseArgs(args, c.ReqData)
			if err != nil {
				return err
			}
			if Debug {
				fmt.Printf("argsmap: %v\n", argsMap)
			}
			if c.ReqData != nil {
				// convert to json map
				in, err = cli.JsonMap(argsMap, c.ReqData)
				if err != nil {
					return err
				}
			} else {
				in = argsMap
			}
			if Debug {
				fmt.Printf("jsonmap: %v\n", in)
			}
		}

		client.Debug = Debug
		if c.StreamOut && c.StreamOutIncremental {
			// print streamed data as it comes
			replyReady := func() {
				check(0, nil, c.ReplyData)
			}
			st, err := client.PostJsonStreamOut(getUri()+c.Path,
				Token, in, c.ReplyData, replyReady)
			return check(st, err, nil)
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
			st, err := client.PostJsonStreamOut(getUri()+c.Path,
				Token, in, c.ReplyData, replyReady)
			return check(st, err, outs)
		} else {
			st, err := client.PostJson(getUri()+c.Path, Token,
				in, c.ReplyData)
			return check(st, err, c.ReplyData)
		}
	}
}

func check(status int, err error, reply interface{}) error {
	// all failure cases result in error getting set (by PostJson)
	if err != nil {
		if status != 0 {
			return fmt.Errorf("%s, %v", http.StatusText(status), err)
		}
		return err
	}
	// success
	if res, ok := reply.(*ormapi.Result); ok && !Parsable {
		// pretty print result
		if res.Message != "" {
			fmt.Println(res.Message)
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
		err = cli.WriteOutput(reply, OutputFormat)
		if err != nil {
			return err
		}
	}
	return nil
}

func genGroup(use, short string, cmds []*Command) *cobra.Command {
	groupCmd := &cobra.Command{
		Use:   use,
		Short: short,
	}

	for _, c := range cmds {
		groupCmd.AddCommand(genCmd(c))
	}
	return groupCmd

}

func PreRunE(cmd *cobra.Command, args []string) error {
	if Token == "" {
		Token = os.Getenv("TOKEN")
	}
	if Token == "" {
		tok, err := ioutil.ReadFile(getTokenFile())
		if err == nil {
			Token = string(tok)
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

func longHelp(short string, c *Command) string {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "%s\n\n", short)

	args := strings.Split(c.RequiredArgs, " ")
	if len(args) > 0 {
		fmt.Fprintf(&buf, "Required Args:\n")
		//w := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
		for _, str := range args {
			//fmt.Fprintf(w, "  %s\t%s\n", argshelp[0], argshelp[1])
			fmt.Fprintf(&buf, "  %s\n", str)
		}
		//w.Flush()
	}
	args = strings.Split(c.OptionalArgs, " ")
	if len(args) > 0 {
		fmt.Fprintf(&buf, "Optional Args:\n")
		for _, str := range args {
			fmt.Fprintf(&buf, "  %s\n", str)
		}
	}
	return buf.String()
}
