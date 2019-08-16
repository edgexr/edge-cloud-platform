package ormclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

type Client struct {
	SkipVerify bool
	Debug      bool
}

func (s *Client) DoLogin(uri, user, pass string) (string, error) {
	login := ormapi.UserLogin{
		Username: user,
		Password: pass,
	}
	result := make(map[string]interface{})
	status, err := s.PostJson(uri+"/login", "", &login, &result)
	if err != nil {
		return "", fmt.Errorf("login error, %s", err.Error())
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("login status %d instead of OK(200)", status)
	}
	tokenI, ok := result["token"]
	if !ok {
		return "", fmt.Errorf("login token not found in response")
	}
	token, ok := tokenI.(string)
	if !ok {
		return "", fmt.Errorf("login token not string")
	}
	return token, nil
}

func (s *Client) CreateUser(uri string, user *ormapi.User) (int, error) {
	return s.PostJson(uri+"/usercreate", "", user, nil)
}

func (s *Client) DeleteUser(uri, token string, user *ormapi.User) (int, error) {
	return s.PostJson(uri+"/auth/user/delete", token, user, nil)
}

func (s *Client) ShowUser(uri, token string, org *ormapi.Organization) ([]ormapi.User, int, error) {
	users := []ormapi.User{}
	status, err := s.PostJson(uri+"/auth/user/show", token, org, &users)
	return users, status, err
}

func (s *Client) CreateController(uri, token string, ctrl *ormapi.Controller) (int, error) {
	return s.PostJson(uri+"/auth/controller/create", token, ctrl, nil)
}

func (s *Client) DeleteController(uri, token string, ctrl *ormapi.Controller) (int, error) {
	return s.PostJson(uri+"/auth/controller/delete", token, ctrl, nil)
}

func (s *Client) ShowController(uri, token string) ([]ormapi.Controller, int, error) {
	ctrls := []ormapi.Controller{}
	status, err := s.PostJson(uri+"/auth/controller/show", token, nil, &ctrls)
	return ctrls, status, err
}

func (s *Client) CreateOrg(uri, token string, org *ormapi.Organization) (int, error) {
	return s.PostJson(uri+"/auth/org/create", token, org, nil)
}

func (s *Client) DeleteOrg(uri, token string, org *ormapi.Organization) (int, error) {
	return s.PostJson(uri+"/auth/org/delete", token, org, nil)
}

func (s *Client) ShowOrg(uri, token string) ([]ormapi.Organization, int, error) {
	orgs := []ormapi.Organization{}
	status, err := s.PostJson(uri+"/auth/org/show", token, nil, &orgs)
	return orgs, status, err
}

func (s *Client) AddUserRole(uri, token string, role *ormapi.Role) (int, error) {
	return s.PostJson(uri+"/auth/role/adduser", token, role, nil)
}

func (s *Client) RemoveUserRole(uri, token string, role *ormapi.Role) (int, error) {
	return s.PostJson(uri+"/auth/role/removeuser", token, role, nil)
}

func (s *Client) ShowUserRole(uri, token string) ([]ormapi.Role, int, error) {
	roles := []ormapi.Role{}
	status, err := s.PostJson(uri+"/auth/role/showuser", token, nil, &roles)
	return roles, status, err
}

func (s *Client) ShowRoleAssignment(uri, token string) ([]ormapi.Role, int, error) {
	roles := []ormapi.Role{}
	status, err := s.PostJson(uri+"/auth/role/assignment/show", token, nil, &roles)
	return roles, status, err
}

func (s *Client) CreateData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error) {
	res := ormapi.Result{}
	var reserr error
	var resstatus int
	status, err := s.PostJsonStreamOut(uri+"/auth/data/create", token, data, &res, func() {
		if res.Code != 0 {
			reserr = fmt.Errorf(res.Message)
			resstatus = res.Code
		}
		cb(&res)
	})
	if reserr != nil {
		return resstatus, reserr
	}
	return status, err
}

func (s *Client) DeleteData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error) {
	res := ormapi.Result{}
	var reserr error
	var resstatus int
	status, err := s.PostJsonStreamOut(uri+"/auth/data/delete", token, data, &res, func() {
		if res.Code != 0 {
			reserr = fmt.Errorf(res.Message)
			resstatus = res.Code
		}
		cb(&res)
	})
	if reserr != nil {
		return resstatus, reserr
	}
	return status, err
}

func (s *Client) ShowData(uri, token string) (*ormapi.AllData, int, error) {
	data := ormapi.AllData{}
	status, err := s.PostJson(uri+"/auth/data/show", token, nil, &data)
	return &data, status, err
}

func (s *Client) UpdateConfig(uri, token string, config map[string]interface{}) (int, error) {
	return s.PostJson(uri+"/auth/config/update", token, config, nil)
}

func (s *Client) ShowConfig(uri, token string) (*ormapi.Config, int, error) {
	config := ormapi.Config{}
	status, err := s.PostJson(uri+"/auth/config/show", token, nil, &config)
	return &config, status, err
}

func (s *Client) RestrictedUserUpdate(uri, token string, user map[string]interface{}) (int, error) {
	return s.PostJson(uri+"/auth/restricted/user/update", token, user, nil)
}

func (s *Client) ShowAuditSelf(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error) {
	resp := []ormapi.AuditResponse{}
	status, err := s.PostJson(uri+"/auth/audit/showself", token, query, &resp)
	return resp, status, err
}

func (s *Client) ShowAuditOrg(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error) {
	resp := []ormapi.AuditResponse{}
	status, err := s.PostJson(uri+"/auth/audit/showorg", token, query, &resp)
	return resp, status, err
}

func (s *Client) PostJsonSend(uri, token string, reqData interface{}) (*http.Response, error) {
	var body io.Reader
	if reqData != nil {
		out, err := json.Marshal(reqData)
		if err != nil {
			return nil, fmt.Errorf("post %s marshal req failed, %s", uri, err.Error())
		}
		if s.Debug {
			fmt.Printf("posting %s\n", string(out))
		}
		body = bytes.NewBuffer(out)
	} else {
		body = nil
	}

	req, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return nil, fmt.Errorf("post %s http req failed, %s", uri, err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}
	tlsConfig := &tls.Config{}
	if s.SkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}
	return client.Do(req)
}

func (s *Client) PostJson(uri, token string, reqData interface{}, replyData interface{}) (int, error) {
	resp, err := s.PostJsonSend(uri, token, reqData)
	if err != nil {
		return 0, fmt.Errorf("post %s client do failed, %s", uri, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && replyData != nil {
		err = json.NewDecoder(resp.Body).Decode(replyData)
		if err != nil && err != io.EOF {
			return resp.StatusCode, fmt.Errorf("post %s decode resp failed, %v", uri, err)
		}
	}
	if resp.StatusCode != http.StatusOK {
		res := ormapi.Result{}
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("post %s decode result failed, %v", uri, err)
		}
		return resp.StatusCode, errors.New(res.Message)
	}
	return resp.StatusCode, nil
}

func (s *Client) PostJsonStreamOut(uri, token string, reqData, replyData interface{}, replyReady func()) (int, error) {
	resp, err := s.PostJsonSend(uri, token, reqData)
	if err != nil {
		return 0, fmt.Errorf("post %s client do failed, %s", uri, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res := ormapi.Result{}
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("post %s decode result failed, %v", uri, err)
		}
		return resp.StatusCode, errors.New(res.Message)
	}
	payload := ormapi.StreamPayload{}
	if replyData != nil {
		payload.Data = replyData
	}

	dec := json.NewDecoder(resp.Body)
	for {
		if replyData != nil {
			// clear passed in buffer for next iteration.
			// replyData must be pointer to object.
			p := reflect.ValueOf(replyData).Elem()
			p.Set(reflect.Zero(p.Type()))
		}

		payload.Result = nil
		err := dec.Decode(&payload)
		if err != nil {
			if err == io.EOF {
				break
			}
			return resp.StatusCode, fmt.Errorf("post %s decode resp failed, %s", uri, err.Error())
		}
		if payload.Result != nil {
			return resp.StatusCode, errors.New(payload.Result.Message)
		}
		if replyReady != nil {
			replyReady()
		}
	}
	return resp.StatusCode, nil
}

func (s *Client) ArtifactoryResync(uri, token string) (int, error) {
	return s.PostJson(uri+"/auth/artifactory/resync", token, nil, nil)
}
