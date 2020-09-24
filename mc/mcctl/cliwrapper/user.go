package cliwrapper

import (
	fmt "fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) DoLogin(uri, user, pass string) (string, error) {
	args := []string{"login", "username=" + user, "password=" + pass}
	out, err := s.run(uri, "", args)
	if err != nil {
		return "", fmt.Errorf("%s, %v", string(out), err)
	}
	return strings.TrimSpace(string(out)), err
}

func (s *Client) CreateUser(uri string, user *ormapi.User) (int, error) {
	args := []string{"user", "create"}
	createuser := &ormapi.CreateUser{
		User: *user,
	}
	return s.runObjs(uri, "", args, createuser, nil)
}

func (s *Client) DeleteUser(uri, token string, user *ormapi.User) (int, error) {
	args := []string{"user", "delete"}
	return s.runObjs(uri, token, args, user, nil)
}

func (s *Client) ShowUser(uri, token string, org *ormapi.Organization) ([]ormapi.User, int, error) {
	args := []string{"user", "show"}
	users := []ormapi.User{}
	st, err := s.runObjs(uri, token, args, org, &users)
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
