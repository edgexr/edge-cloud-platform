package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) CreateAlertReceiver(uri, token string, receiver *ormapi.AlertReceiver) (int, error) {
	args := []string{"alertreceiver", "create"}
	return s.runObjs(uri, token, args, receiver, nil)
}

func (s *Client) DeleteAlertReceiver(uri, token string, receiver *ormapi.AlertReceiver) (int, error) {
	args := []string{"alertreceiver", "delete"}
	return s.runObjs(uri, token, args, receiver, nil)
}

func (s *Client) ShowAlertReceiver(uri, token string, in *ormapi.AlertReceiver) ([]ormapi.AlertReceiver, int, error) {
	args := []string{"alertreceiver", "show"}
	receivers := []ormapi.AlertReceiver{}
	st, err := s.runObjs(uri, token, args, in, &receivers)
	return receivers, st, err
}
