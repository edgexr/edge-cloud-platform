// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chargify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/edgexr/edge-cloud/vault"
)

type BillingService struct{}

type accountCreds struct {
	ApiKey string `json:"apikey"`
	Url    string `json:"url"`
}

func (bs *BillingService) Init(ctx context.Context, vaultConfig *vault.Config) error {
	creds := accountCreds{}
	err := vault.GetData(vaultConfig, vaultPath, 0, &creds)
	apiKey = creds.ApiKey
	siteName = creds.Url
	if err != nil {
		// if the creds weren't in vault check env vars
		if apiKey == "" {
			apiKey = os.Getenv("CHARGIFY_API_KEY")
		}
		if siteName == "" {
			siteName = os.Getenv("CHARGIFY_SITE_NAME")
		}
		if apiKey == "" || siteName == "" {
			return err
		}
	}

	// since we can potentially be sending stuff like credit card info, make sure the url is secure
	if !strings.Contains(siteName, "https") {
		return fmt.Errorf("insecure chargify site")
	}

	return nil
}

func (bs *BillingService) GetType() string {
	return "chargify"
}

func newChargifyReq(method, endpoint string, payload interface{}) (*http.Response, error) {
	url := siteName + endpoint
	var body io.Reader
	if payload != nil {
		marshalled, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal %+v, err: %v", payload, err)
		}
		body = bytes.NewReader(marshalled)
	} else {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %v\n", err)
	}
	req.SetBasicAuth(apiKey, apiPassword)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	return client.Do(req)
}
