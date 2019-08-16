package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) ShowAuditSelf(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error) {
	args := []string{"audit", "showself"}
	resp := []ormapi.AuditResponse{}
	st, err := s.runObjs(uri, token, args, query, &resp)
	return resp, st, err
}

func (s *Client) ShowAuditOrg(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error) {
	args := []string{"audit", "showorg"}
	resp := []ormapi.AuditResponse{}
	st, err := s.runObjs(uri, token, args, query, &resp)
	return resp, st, err
}
