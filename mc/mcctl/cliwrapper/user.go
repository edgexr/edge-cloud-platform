package cliwrapper

import (
	fmt "fmt"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) DoLogin(uri, user, pass, otp, apikeyid, apikey string) (string, bool, error) {
	args := []string{"login"}
	if user != "" {
		args = append(args, "username="+user)
	}
	if pass != "" {
		args = append(args, "password="+pass)
	}
	if otp != "" {
		args = append(args, "totp="+otp)
	}
	if apikeyid != "" {
		args = append(args, "apikeyid="+apikeyid)
	}
	if apikey != "" {
		args = append(args, "apikey="+apikey)
	}
	admin := false
	out, err := s.run(uri, "", args)
	if err != nil {
		return "", admin, fmt.Errorf("%s, %v", string(out), err)
	}
	if _, err := os.Stat(ormctl.GetAdminFile()); err == nil {
		admin = true
	}
	return strings.TrimSpace(string(out)), admin, err
}

func (s *Client) CreateUser(uri string, user *ormapi.User) (*ormapi.UserResponse, int, error) {
	args := []string{"user", "create"}
	createuser := &ormapi.CreateUser{
		User: *user,
	}
	resp := ormapi.UserResponse{}
	st, err := s.runObjs(uri, "", args, createuser, &resp)
	return &resp, st, err
}

func (s *Client) DeleteUser(uri, token string, user *ormapi.User) (int, error) {
	args := []string{"user", "delete"}
	return s.runObjs(uri, token, args, user, nil)
}

func (s *Client) UpdateUser(uri, token string, createUserJSON string) (*ormapi.UserResponse, int, error) {
	args := []string{"user", "update"}
	resp := ormapi.UserResponse{}
	st, err := s.runObjs(uri, token, args, createUserJSON, &resp)
	return &resp, st, err
}

func (s *Client) ShowUser(uri, token string, filter *ormapi.ShowUser) ([]ormapi.User, int, error) {
	args := []string{"user", "show"}
	users := []ormapi.User{}
	st, err := s.runObjs(uri, token, args, filter, &users)
	return users, st, err
}

func (s *Client) RestrictedUserUpdate(uri, token string, user map[string]interface{}) (int, error) {
	args := []string{"user", "restricteduserupdate"}
	return s.runObjs(uri, token, args, user, nil)
}

func (s *Client) NewPassword(uri, token, password string) (int, error) {
	newpw := ormapi.NewPassword{
		Password: password,
	}
	args := []string{"user", "newpass"}
	return s.runObjs(uri, token, args, newpw, nil)
}
