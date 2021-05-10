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

func getLoginCmd() *cobra.Command {
	apiCmd := ormctl.MustGetCommand("Login")
	cliCmd := ConvertCmd(apiCmd)
	cliCmd.Run = runLogin(apiCmd.Path)
	return cliCmd.GenCmd()
}

func runLogin(path string) func(c *cli.Command, args []string) error {
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
		st, err := client.PostJson(getUri()+path, "", &login, &out)
		if err != nil {
			return err
		}
		token, admin, err := ormctl.ParseLoginResp(out, st, err)
		if err != nil {
			return err
		}

		if cli.Parsable {
			c.WriteOutput(out, cli.OutputFormat)
			return nil
		}

		fmt.Println("login successful")
		err = ioutil.WriteFile(getTokenFile(), []byte(token), 0600)
		if err != nil {
			fmt.Printf("warning, cannot save token file %s, %v\n", getTokenFile(), err)
			fmt.Printf("token: %s\n", token)
		} else {
			fmt.Printf("token saved to %s\n", getTokenFile())
		}
		if err == nil && admin {
			ioutil.WriteFile(GetAdminFile(), []byte{}, 0600)
		} else {
			os.Remove(GetAdminFile())
		}
		return nil
	}
}

func getDevCloudletShowCommand() *cobra.Command {
	apiCmd := ormctl.MustGetCommand("ShowCloudlet")
	cliCmd := ConvertCmd(apiCmd)
	cliCmd.Use = "cloudletshow"
	cliCmd.Short = "View cloudlets"
	return cliCmd.GenCmd()
}
