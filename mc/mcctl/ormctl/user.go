package ormctl

import (
	"fmt"
	"io/ioutil"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetUserCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:            "create",
		RequiredArgs:   "name email",
		OptionalArgs:   "nickname familyname givenname callbackurl enabletotp metadata",
		AliasArgs:      "name=user.name email=user.email nickname=user.nickname familyname=user.familyname givenname=user.givenname password=user.passhash callbackurl=verify.callbackurl enabletotp=user.enabletotp metadata=user.metadata",
		PasswordArg:    "user.passhash",
		VerifyPassword: true,
		ReqData:        &ormapi.CreateUser{},
		ReplyData:      &ormapi.UserResponse{},
		Run:            runRest("/usercreate"),
	}, &cli.Command{
		Use:          "delete",
		RequiredArgs: "name",
		ReqData:      &ormapi.User{},
		Run:          runRest("/auth/user/delete"),
	}, &cli.Command{
		Use:          "update",
		OptionalArgs: "email nickname familyname givenname callbackurl enabletotp metadata",
		AliasArgs:    "email=user.email nickname=user.nickname familyname=user.familyname givenname=user.givenname callbackurl=verify.callbackurl enabletotp=user.enabletotp metadata=user.metadata",
		ReqData:      &ormapi.CreateUser{},
		ReplyData:    &ormapi.UserResponse{},
		Run:          runRest("/auth/user/update"),
	}, &cli.Command{
		Use:          "show",
		ReqData:      &ormapi.Organization{},
		OptionalArgs: "orgname",
		AliasArgs:    "orgname=name",
		ReplyData:    &[]ormapi.User{},
		Run:          runRest("/auth/user/show"),
	}, &cli.Command{
		Use:       "current",
		ReplyData: &ormapi.User{},
		Run:       runRest("/auth/user/current"),
	}, &cli.Command{
		Use:            "newpass",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.NewPassword{},
		Run:            runRest("/auth/user/newpass"),
	}, &cli.Command{
		Use:          "resendverify",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Run:          runRest("/resendverify"),
	}, &cli.Command{
		Use:          "verifyemail",
		RequiredArgs: "token",
		ReqData:      &ormapi.Token{},
		Run:          runRest("/verifyemail"),
	}, &cli.Command{
		Use:          "passwordresetrequest",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Run:          runRest("/passwordresetrequest"),
	}, &cli.Command{
		Use:            "passwordreset",
		RequiredArgs:   "token",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.PasswordReset{},
		Run:            runRest("/passwordreset"),
	}, &cli.Command{
		Use:          "restricteduserupdate",
		OptionalArgs: "name email emailverified familyname givenname nickname locked",
		ReqData:      &ormapi.User{},
		Run:          runRest("/auth/restricted/user/update"),
	}, &cli.Command{
		Use:          "createapikey",
		RequiredArgs: "org description",
		OptionalArgs: "permissions:#.action permissions:#.resource",
		AliasArgs:    "org=userapikey.org description=userapikey.description",
		ReqData:      &ormapi.CreateUserApiKey{},
		ReplyData:    &ormapi.CreateUserApiKey{},
		Run:          runRest("/auth/user/create/apikey"),
	}, &cli.Command{
		Use:          "deleteapikey",
		RequiredArgs: "apikeyid",
		AliasArgs:    "apikeyid=userapikey.id",
		ReqData:      &ormapi.CreateUserApiKey{},
		Run:          runRest("/auth/user/delete/apikey"),
	}, &cli.Command{
		Use:          "showapikey",
		ReqData:      &ormapi.CreateUserApiKey{},
		OptionalArgs: "apikeyid",
		AliasArgs:    "apikeyid=userapikey.id",
		ReplyData:    &[]ormapi.CreateUserApiKey{},
		Run:          runRest("/auth/user/show/apikey"),
	}}
	return cli.GenGroup("user", "manage users", cmds)
}

func GetLoginCmd() *cobra.Command {
	cmd := cli.Command{
		Use:          "login",
		OptionalArgs: "name totp apikeyid apikey",
		Run:          runLogin,
	}
	return cmd.GenCmd()
}

func runLogin(c *cli.Command, args []string) error {
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
	token, err := client.DoLogin(getUri(), login.Username, login.Password, login.TOTP, login.ApiKeyId, login.ApiKey)
	if err != nil {
		return err
	}

	if cli.Parsable {
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
