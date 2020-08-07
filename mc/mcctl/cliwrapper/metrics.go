package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) ShowAppMetrics(uri, token string, query *ormapi.RegionAppInstMetrics) (*ormapi.AllMetrics, int, error) {
	args := []string{"metrics", "app"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}
func (s *Client) ShowClusterMetrics(uri, token string, query *ormapi.RegionClusterInstMetrics) (*ormapi.AllMetrics, int, error) {
	args := []string{"metrics", "cluster"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}

func (s *Client) ShowCloudletMetrics(uri, token string, query *ormapi.RegionCloudletMetrics) (*ormapi.AllMetrics, int, error) {
	args := []string{"metrics", "cloudlet"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}

func (s *Client) ShowClientMetrics(uri, token string, query *ormapi.RegionClientMetrics) (*ormapi.AllMetrics, int, error) {
	args := []string{"metrics", "client"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}
