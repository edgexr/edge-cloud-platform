package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) ShowAppUsage(uri, token string, query *ormapi.RegionAppInstUsage) (*ormapi.AllMetrics, int, error) {
	args := []string{"usage", "app"}
	usage := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &usage)
	return &usage, st, err
}

func (s *Client) ShowClusterUsage(uri, token string, query *ormapi.RegionClusterInstUsage) (*ormapi.AllMetrics, int, error) {
	args := []string{"usage", "cluster"}
	usage := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &usage)
	return &usage, st, err
}

func (s *Client) ShowCloudletPoolUsage(uri, token string, query *ormapi.RegionCloudletPoolUsage) (*ormapi.AllMetrics, int, error) {
	args := []string{"usage", "cloudletpool"}
	usage := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &usage)
	return &usage, st, err
}
