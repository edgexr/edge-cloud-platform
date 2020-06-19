package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Client) CreateOrgCloudletPool(uri, token string, op *ormapi.OrgCloudletPool) (int, error) {
	args := []string{"orgcloudletpool", "create"}
	return s.runObjs(uri, token, args, op, nil)
}

func (s *Client) DeleteOrgCloudletPool(uri, token string, op *ormapi.OrgCloudletPool) (int, error) {
	args := []string{"orgcloudletpool", "delete"}
	return s.runObjs(uri, token, args, op, nil)
}

func (s *Client) ShowOrgCloudletPool(uri, token string) ([]ormapi.OrgCloudletPool, int, error) {
	args := []string{"orgcloudletpool", "show"}
	ops := []ormapi.OrgCloudletPool{}
	st, err := s.runObjs(uri, token, args, nil, &ops)
	return ops, st, err
}

func (s *Client) ShowOrgCloudlet(uri, token string, in *ormapi.OrgCloudlet) ([]edgeproto.Cloudlet, int, error) {
	args := []string{"orgcloudlet", "show"}
	out := []edgeproto.Cloudlet{}
	st, err := s.runObjs(uri, token, args, in, &out)
	return out, st, err
}

func (s *Client) ShowOrgCloudletInfo(uri, token string, in *ormapi.OrgCloudlet) ([]edgeproto.CloudletInfo, int, error) {
	args := []string{"orgcloudletinfo", "show"}
	out := []edgeproto.CloudletInfo{}
	st, err := s.runObjs(uri, token, args, in, &out)
	return out, st, err
}
