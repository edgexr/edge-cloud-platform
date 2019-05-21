package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) CreateController(uri, token string, ctrl *ormapi.Controller) (int, error) {
	args := []string{"controller", "create"}
	return s.runObjs(uri, token, args, ctrl, nil)
}

func (s *Client) DeleteController(uri, token string, ctrl *ormapi.Controller) (int, error) {
	args := []string{"controller", "delete"}
	return s.runObjs(uri, token, args, ctrl, nil)
}

func (s *Client) ShowController(uri, token string) ([]ormapi.Controller, int, error) {
	args := []string{"controller", "show"}
	ctrls := []ormapi.Controller{}
	st, err := s.runObjs(uri, token, args, nil, &ctrls)
	return ctrls, st, err
}
