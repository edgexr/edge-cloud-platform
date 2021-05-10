package mctestclient

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (s *Client) DoLogin(uri, user, pass, otp, apikeyid, apikey string) (string, bool, error) {
	login := ormapi.UserLogin{
		Username: user,
		Password: pass,
		TOTP:     otp,
		ApiKeyId: apikeyid,
		ApiKey:   apikey,
	}
	return ormctl.ParseLoginResp(s.Login(uri, &login))
}
