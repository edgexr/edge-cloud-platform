// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
