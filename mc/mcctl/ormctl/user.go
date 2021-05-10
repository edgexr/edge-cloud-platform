package ormctl

import (
	fmt "fmt"
	"net/http"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const UserGroup = "User"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:           "CreateUser",
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
		Path:           "/usercreate",
	}, &ApiCommand{
		Name:         "DeleteUser",
		Use:          "delete",
		Short:        "Delete an existing user",
		RequiredArgs: "name",
		Comments:     ormapi.UserComments,
		ReqData:      &ormapi.User{},
		Path:         "/auth/user/delete",
	}, &ApiCommand{
		Name:         "UpdateUser",
		Use:          "update",
		Short:        "Update a user",
		OptionalArgs: "email nickname familyname givenname enabletotp metadata",
		AliasArgs:    strings.Join(CreateUserAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserComments, CreateUserAliasArgs),
		ReqData:      &ormapi.CreateUser{},
		ReplyData:    &ormapi.UserResponse{},
		Path:         "/auth/user/update",
	}, &ApiCommand{
		Name:         "ShowUser",
		Use:          "show",
		Short:        "Show users",
		ReqData:      &ormapi.ShowUser{},
		OptionalArgs: "name email emailverified familyname givenname nickname locked enabletotp orgname role",
		Comments:     ormapi.UserComments,
		ReplyData:    &[]ormapi.User{},
		Path:         "/auth/user/show",
	}, &ApiCommand{
		Name:      "CurrentUser",
		Use:       "current",
		Short:     "Show the currently logged in user",
		ReplyData: &ormapi.User{},
		Path:      "/auth/user/current",
	}, &ApiCommand{
		Name:           "NewPassword",
		Use:            "newpass",
		Short:          "Set a new password, requires the existing password",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.NewPassword{},
		Path:           "/auth/user/newpass",
	}, &ApiCommand{
		Name:         "ResendVerify",
		Short:        "Request that the user verification email be resent",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Path:         "/resendverify",
	}, &ApiCommand{
		Name:         "VerifyEmail",
		Short:        "Verify a user's email account from the token in the email",
		RequiredArgs: "token",
		ReqData:      &ormapi.Token{},
		Path:         "/verifyemail",
	}, &ApiCommand{
		Name:         "PasswordResetRequest",
		Short:        "Request a password reset email to be sent to the user's email",
		RequiredArgs: "email",
		ReqData:      &ormapi.EmailRequest{},
		Path:         "/passwordresetrequest",
	}, &ApiCommand{
		Name:           "PasswordReset",
		Use:            "passwordreset",
		Short:          "Reset the password using the token from the password reset email",
		RequiredArgs:   "token",
		PasswordArg:    "password",
		VerifyPassword: true,
		ReqData:        &ormapi.PasswordReset{},
		Path:           "/passwordreset",
	}, &ApiCommand{
		Name:         "CreateUserApiKey",
		Short:        "Create an API key for reduced access, typically for automation",
		RequiredArgs: "org description",
		OptionalArgs: "permissions:#.action permissions:#.resource",
		AliasArgs:    strings.Join(CreateUserApiKeyAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserApiKeyComments, CreateUserApiKeyAliasArgs),
		ReqData:      &ormapi.CreateUserApiKey{},
		ReplyData:    &ormapi.CreateUserApiKey{},
		Path:         "/auth/user/create/apikey",
	}, &ApiCommand{
		Name:         "DeleteUserApiKey",
		Short:        "Delete an API key",
		RequiredArgs: "apikeyid",
		AliasArgs:    strings.Join(CreateUserApiKeyAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserApiKeyComments, CreateUserApiKeyAliasArgs),
		ReqData:      &ormapi.CreateUserApiKey{},
		Path:         "/auth/user/delete/apikey",
	}, &ApiCommand{
		Name:         "ShowUserApiKey",
		Short:        "Show existing API keys",
		ReqData:      &ormapi.CreateUserApiKey{},
		OptionalArgs: "apikeyid",
		AliasArgs:    strings.Join(CreateUserApiKeyAliasArgs, " "),
		Comments:     aliasedComments(ormapi.CreateUserApiKeyComments, CreateUserApiKeyAliasArgs),
		ReplyData:    &[]ormapi.CreateUserApiKey{},
		Path:         "/auth/user/show/apikey",
	}}
	AllApis.AddGroup(UserGroup, "Manage your account or other users", cmds)

	cmd := &ApiCommand{
		Name:         "RestrictedUpdateUser",
		Short:        "Admin-only update of various user fields, requires name or email",
		OptionalArgs: "name email emailverified familyname givenname nickname locked",
		Comments:     ormapi.UserComments,
		ReqData:      &ormapi.User{},
		Path:         "/auth/restricted/user/update",
		IsUpdate:     true,
	}
	AllApis.AddCommand(cmd)

	cmd = &ApiCommand{
		Name:         "Login",
		Short:        "Login using account credentials",
		OptionalArgs: "name totp apikeyid apikey",
		ReqData:      &ormapi.UserLogin{},
		ReplyData:    &map[string]interface{}{},
		Path:         "/login",
	}
	AllApis.AddCommand(cmd)
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

// convenience func - returns token, admin, error
func ParseLoginResp(resp map[string]interface{}, status int, err error) (string, bool, error) {
	if err != nil {
		return "", false, fmt.Errorf("login error, %s", err.Error())
	}
	if status != http.StatusOK {
		return "", false, fmt.Errorf("login status %d instead of OK(200)", status)
	}
	tokenI, ok := resp["token"]
	if !ok {
		return "", false, fmt.Errorf("login token not found in response")
	}
	token, ok := tokenI.(string)
	if !ok {
		return "", false, fmt.Errorf("login token not string")
	}
	admin := false
	if adminI, ok := resp["admin"]; ok {
		if adminB, ok := adminI.(bool); ok {
			admin = adminB
		}
	}
	return token, admin, nil
}
