package ormctl

import (
	"fmt"
	"io/ioutil"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/cli"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetUserCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:            "create",
		RequiredArgs:   "name email",
		OptionalArgs:   "nickname familyname givenname callbackurl",
		AliasArgs:      "name=user.name email=user.email nickname=user.nickname familyname=user.familyname givenname=user.givenname password=user.passhash callbackurl=verify.callbackurl",
		PasswordArg:    "user.passhash",
		VerifyPassword: true,
		ReqData:        &ormapi.CreateUser{},
		SendObj:        true,
		Path:           "/usercreate",
	}, &Command{
		Use:          "delete",
		RequiredArgs: "name",
		ReqData:      &ormapi.User{},
		Path:         "/auth/user/delete",
	}, &Command{
		Use:          "show",
		ReqData:      &ormapi.Organization{},
		OptionalArgs: "orgname",
		AliasArgs:    "orgname=name",
		ReplyData:    &[]ormapi.User{},
		Path:         "/auth/user/show",
	}, &Command{
		Use:       "current",
		ReplyData: &ormapi.User{},
		Path:      "/auth/user/current",
	}, &Command{
		Use:            "newpass",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.NewPassword{},
		Path:           "/auth/user/newpass",
	}, &Command{
		Use:          "resendverify",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Path:         "/resendverify",
	}, &Command{
		Use:          "verifyemail",
		RequiredArgs: "token",
		ReqData:      &ormapi.Token{},
		Path:         "/verifyemail",
	}, &Command{
		Use:          "passwordresetrequest",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Path:         "/passwordresetrequest",
	}, &Command{
		Use:            "passwordreset",
		RequiredArgs:   "token",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.PasswordReset{},
		Path:           "/passwordreset",
	}, &Command{
		Use:          "restricteduserupdate",
		OptionalArgs: "name email emailverified familyname givenname nickname locked",
		ReqData:      &ormapi.User{},
		Path:         "/auth/restricted/user/update",
	}}
	return genGroup("user", "manage users", cmds)
}

func GetLoginCmd() *cobra.Command {
	cmd := genCmd(&Command{
		Use:          "login",
		RequiredArgs: "name",
		Run:          runLogin,
	})
	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	input := cli.Input{
		RequiredArgs: []string{"name"},
		PasswordArg:  "password",
		AliasArgs:    []string{"name=username"},
	}
	login := ormapi.UserLogin{}
	_, err := input.ParseArgs(args, &login)
	if err != nil {
		return err
	}
	token, err := client.DoLogin(getUri(), login.Username, login.Password)
	if err != nil {
		return err
	}

	if Parsable {
		fmt.Printf("%s\n", token)
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
	return nil
}
