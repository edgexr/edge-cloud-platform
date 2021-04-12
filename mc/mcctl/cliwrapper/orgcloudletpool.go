package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Client) CreateCloudletPoolAccessInvitation(uri, token string, op *ormapi.OrgCloudletPool) (int, error) {
	args := []string{"cloudletpoolinvitation", "create"}
	return s.runObjs(uri, token, args, op, nil)
}

func (s *Client) DeleteCloudletPoolAccessInvitation(uri, token string, op *ormapi.OrgCloudletPool) (int, error) {
	args := []string{"cloudletpoolinvitation", "delete"}
	return s.runObjs(uri, token, args, op, nil)
}

func (s *Client) ShowCloudletPoolAccessInvitation(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error) {
	args := []string{"cloudletpoolinvitation", "show"}
	ops := []ormapi.OrgCloudletPool{}
	st, err := s.runObjs(uri, token, args, filter, &ops)
	return ops, st, err
}

func (s *Client) CreateCloudletPoolAccessResponse(uri, token string, op *ormapi.OrgCloudletPool) (int, error) {
	args := []string{"cloudletpoolresponse", "create"}
	return s.runObjs(uri, token, args, op, nil)
}

func (s *Client) DeleteCloudletPoolAccessResponse(uri, token string, op *ormapi.OrgCloudletPool) (int, error) {
	args := []string{"cloudletpoolresponse", "delete"}
	return s.runObjs(uri, token, args, op, nil)
}

func (s *Client) ShowCloudletPoolAccessResponse(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error) {
	args := []string{"cloudletpoolresponse", "show"}
	ops := []ormapi.OrgCloudletPool{}
	st, err := s.runObjs(uri, token, args, filter, &ops)
	return ops, st, err
}

func (s *Client) ShowCloudletPoolAccessGranted(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error) {
	args := []string{"cloudletpoolresponse", "showgranted"}
	ops := []ormapi.OrgCloudletPool{}
	st, err := s.runObjs(uri, token, args, filter, &ops)
	return ops, st, err
}

func (s *Client) ShowCloudletPoolAccessPending(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error) {
	args := []string{"cloudletpoolresponse", "showpending"}
	ops := []ormapi.OrgCloudletPool{}
	st, err := s.runObjs(uri, token, args, filter, &ops)
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
