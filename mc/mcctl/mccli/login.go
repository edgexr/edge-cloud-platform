package mccli

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func (s *RootCommand) getLoginCmd() *cobra.Command {
	apiCmd := ormctl.MustGetCommand("Login")
	cliCmd := s.ConvertCmd(apiCmd)
	cliCmd.Run = s.runLogin(apiCmd.Path)
	return cliCmd.GenCmd()
}

func (s *RootCommand) runLogin(path string) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		input := cli.Input{
			PasswordArg: "password",
			ApiKeyArg:   "apikey",
			AliasArgs:   []string{"name=username"},
		}
		login := ormapi.UserLogin{}
		_, err := input.ParseArgs(args, &login)
		if err != nil {
			return err
		}
		out := map[string]interface{}{}
		st, err := s.client.PostJson(s.getUri()+path, "", &login, &out)
		if err != nil {
			return err
		}

		wr := c.CobraCmd.OutOrStdout()
		if cli.Parsable {
			c.WriteOutput(wr, out, cli.OutputFormat)
			return nil
		}

		token, admin, err := ormctl.ParseLoginResp(out, st, err)
		if err != nil {
			return err
		}
		fmt.Fprintln(wr, "login successful")
		err = ioutil.WriteFile(GetTokenFile(), []byte(token), 0600)
		if err != nil {
			fmt.Fprintf(wr, "warning, cannot save token file %s, %v\n", GetTokenFile(), err)
			fmt.Fprintf(wr, "token: %s\n", token)
		} else {
			fmt.Fprintf(wr, "token saved to %s\n", GetTokenFile())
		}
		if err == nil && admin {
			ioutil.WriteFile(GetAdminFile(), []byte{}, 0600)
		} else {
			os.Remove(GetAdminFile())
		}
		return nil
	}
}

func (s *RootCommand) getDevCloudletShowCommand() *cobra.Command {
	apiCmd := ormctl.MustGetCommand("ShowCloudlet")
	cliCmd := s.ConvertCmd(apiCmd)
	cliCmd.Use = "cloudletshow"
	cliCmd.Short = "View cloudlets"
	return cliCmd.GenCmd()
}
