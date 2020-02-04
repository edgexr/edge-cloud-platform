package cliwrapper

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) RunCommandOut(uri, token string, in *ormapi.RegionExecRequest) (string, error) {
	args := []string{"region", "RunCommand"}
	var out string
	noconfig := strings.Split("Offer,Answer,Err", ",")
	_, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	return out, err
}

func (s *Client) ShowLogsOut(uri, token string, in *ormapi.RegionExecRequest) (string, error) {
	args := []string{"region", "ShowLogs"}
	var out string
	noconfig := strings.Split("Offer,Answer,Err", ",")
	_, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	return out, err
}
