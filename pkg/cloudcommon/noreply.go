package cloudcommon

import (
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

type EmailAccount struct {
	Email    string `json:"email"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Smtp     string `json:"smtp"`
	SmtpPort string `json:"smtpport"`
	SmtpTLS  bool   `json:"smtptls"`
}

func GetNoreply(vaultConfig *vault.Config) (*EmailAccount, error) {
	noreply := EmailAccount{SmtpTLS: true} // default tls to true
	err := vault.GetData(vaultConfig,
		"/secret/data/accounts/noreplyemail", 0, &noreply)
	if err != nil {
		return nil, err
	}
	if noreply.SmtpPort == "" {
		noreply.SmtpPort = "587"
	}
	return &noreply, nil
}
