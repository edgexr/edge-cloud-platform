package cliwrapper

import (
	"encoding/json"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) CreateData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error) {
	dataStr, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	args := []string{"alldata", "create", "--data", string(dataStr)}
	out := []ormapi.Result{}
	st, err := s.runObjs(uri, token, args, nil, &out)
	for _, res := range out {
		cb(&res)
	}
	return st, err
}

func (s *Client) DeleteData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error) {
	dataStr, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	args := []string{"alldata", "delete", "--data", string(dataStr)}
	out := []ormapi.Result{}
	st, err := s.runObjs(uri, token, args, nil, &out)
	for _, res := range out {
		cb(&res)
	}
	return st, err
}

func (s *Client) ShowData(uri, token string) (*ormapi.AllData, int, error) {
	args := []string{"alldata", "show"}
	alldata := ormapi.AllData{}
	st, err := s.runObjs(uri, token, args, nil, &alldata)
	return &alldata, st, err
}
