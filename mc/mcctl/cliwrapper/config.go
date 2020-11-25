package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) UpdateConfig(uri, token string, config map[string]interface{}) (int, error) {
	args := []string{"config", "update"}
	return s.runObjs(uri, token, args, config, nil)
}

func (s *Client) ResetConfig(uri, token string) (int, error) {
	args := []string{"config", "reset"}
	return s.runObjs(uri, token, args, nil, nil)
}

func (s *Client) ShowConfig(uri, token string) (*ormapi.Config, int, error) {
	args := []string{"config", "show"}
	config := ormapi.Config{}
	st, err := s.runObjs(uri, token, args, nil, &config)
	return &config, st, err
}

func (s *Client) PublicConfig(uri string) (*ormapi.Config, int, error) {
	args := []string{"config", "public"}
	config := ormapi.Config{}
	st, err := s.runObjs(uri, "", args, nil, &config)
	return &config, st, err
}
