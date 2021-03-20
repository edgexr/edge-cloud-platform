package ormctl

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetUserCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:            "create",
		Short:          "Create a new user",
		RequiredArgs:   "name email",
		OptionalArgs:   "nickname familyname givenname enabletotp metadata",
		AliasArgs:      strings.Join(CreateUserAliasArgs, " "),
		Comments:       aliasedComments(ormapi.CreateUserComments, CreateUserAliasArgs),
		PasswordArg:    "user.passhash",
		VerifyPassword: true,
		ReqData:        &ormapi.CreateUser{},
		ReplyData:      &ormapi.UserResponse{},
		Run:            runRest("/usercreate"),
	}, &cli.Command{
		Use:          "delete",
		Short:        "Delete an existing user",
		RequiredArgs: "name",
		Comments:     ormapi.UserComments,
		ReqData:      &ormapi.User{},
		Run:          runRest("/auth/user/delete"),
	}, &cli.Command{
		Use:          "update",
		Short:        "Update a user",
		OptionalArgs: "email nickname familyname givenname enabletotp metadata",
		AliasArgs:    strings.Join(CreateUserAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserComments, CreateUserAliasArgs),
		ReqData:      &ormapi.CreateUser{},
		ReplyData:    &ormapi.UserResponse{},
		Run:          runRest("/auth/user/update"),
	}, &cli.Command{
		Use:          "show",
		Short:        "Show users",
		ReqData:      &ormapi.ShowUser{},
		OptionalArgs: "name email emailverified familyname givenname nickname locked enabletotp orgname role",
		Comments:     ormapi.UserComments,
		ReplyData:    &[]ormapi.User{},
		Run:          runRest("/auth/user/show"),
	}, &cli.Command{
		Use:       "current",
		Short:     "Show the currently logged in user",
		ReplyData: &ormapi.User{},
		Run:       runRest("/auth/user/current"),
	}, &cli.Command{
		Use:            "newpass",
		Short:          "Set a new password, requires the existing password",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.NewPassword{},
		Run:            runRest("/auth/user/newpass"),
	}, &cli.Command{
		Use:          "resendverify",
		Short:        "Request that the user verification email be resent",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Run:          runRest("/resendverify"),
	}, &cli.Command{
		Use:          "verifyemail",
		Short:        "Verify a user's email account from the token in the email",
		RequiredArgs: "token",
		ReqData:      &ormapi.Token{},
		Run:          runRest("/verifyemail"),
	}, &cli.Command{
		Use:          "passwordresetrequest",
		Short:        "Request a password reset email to be sent to the user's email",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Run:          runRest("/passwordresetrequest"),
	}, &cli.Command{
		Use:            "passwordreset",
		Short:          "Reset the password using the token from the password reset email",
		RequiredArgs:   "token",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.PasswordReset{},
		Run:            runRest("/passwordreset"),
	}, &cli.Command{
		Use:          "createapikey",
		Short:        "Create an API key for reduced access, typically for automation",
		RequiredArgs: "org description",
		OptionalArgs: "permissions:#.action permissions:#.resource",
		AliasArgs:    strings.Join(CreateUserApiKeyAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserApiKeyComments, CreateUserApiKeyAliasArgs),
		ReqData:      &ormapi.CreateUserApiKey{},
		ReplyData:    &ormapi.CreateUserApiKey{},
		Run:          runRest("/auth/user/create/apikey"),
	}, &cli.Command{
		Use:          "deleteapikey",
		Short:        "Delete an API key",
		RequiredArgs: "apikeyid",
		AliasArgs:    strings.Join(CreateUserApiKeyAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserApiKeyComments, CreateUserApiKeyAliasArgs),
		ReqData:      &ormapi.CreateUserApiKey{},
		Run:          runRest("/auth/user/delete/apikey"),
	}, &cli.Command{
		Use:          "showapikey",
		Short:        "Show existing API keys",
		ReqData:      &ormapi.CreateUserApiKey{},
		OptionalArgs: "apikeyid",
		AliasArgs:    strings.Join(CreateUserApiKeyAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserApiKeyComments, CreateUserApiKeyAliasArgs),
		ReplyData:    &[]ormapi.CreateUserApiKey{},
		Run:          runRest("/auth/user/show/apikey"),
	}}
	return cli.GenGroup("user", "Manage your account or other users", cmds)
}

func GetRestrictedUserUpdateCmd() *cobra.Command {
	cmd := cli.Command{
		Use:          "restricteduserupdate",
		Short:        "Admin-only update of various user fields, requires name or email",
		OptionalArgs: "name email emailverified familyname givenname nickname locked",
		Comments:     ormapi.UserComments,
		ReqData:      &ormapi.User{},
		Run:          runRest("/auth/restricted/user/update"),
	}
	return cmd.GenCmd()
}

func GetLoginCmd() *cobra.Command {
	cmd := cli.Command{
		Use:          "login",
		Short:        "Login using account credentials",
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
	token, admin, err := client.DoLogin(getUri(), login.Username, login.Password, login.TOTP, login.ApiKeyId, login.ApiKey)
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
	if err == nil && admin {
		ioutil.WriteFile(GetAdminFile(), []byte{}, 0600)
	} else {
		os.Remove(GetAdminFile())
	}
	return nil
}

var CreateUserAliasArgs = []string{
	"name=user.name",
	"email=user.email",
	"nickname=user.nickname",
	"familyname=user.familyname",
	"givenname=user.givenname",
	"password=user.passhash",
	"callbackurl=verify.callbackurl",
	"enabletotp=user.enabletotp",
	"metadata=user.metadata",
}

var CreateUserApiKeyAliasArgs = []string{
	"org=userapikey.org",
	"description=userapikey.description",
	"apikeyid=userapikey.id",
}
