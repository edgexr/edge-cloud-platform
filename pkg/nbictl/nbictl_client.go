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

package nbictl

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

type ClientConfig struct {
	bearerToken string
	tlsConfig   *tls.Config
	skipVerify  bool
}

func getURL(addr string) string {
	return addr + cloudcommon.NBIRootPath
}

type ClientConfigOp func(cfg *ClientConfig)

func WithBearerToken(token string) ClientConfigOp {
	return func(cfg *ClientConfig) {
		cfg.bearerToken = token
	}
}

func WithTLSConfig(tc *tls.Config) ClientConfigOp {
	return func(cfg *ClientConfig) {
		cfg.tlsConfig = tc
	}
}

func WithSkipVerify() ClientConfigOp {
	return func(cfg *ClientConfig) {
		cfg.skipVerify = true
	}
}

func BasicClient(addr, bearerToken string, skipVerify bool) (*nbi.ClientWithResponses, error) {
	return NewClient(addr, WithBearerToken(bearerToken), WithSkipVerify())
}

func NewClient(addr string, ops ...ClientConfigOp) (*nbi.ClientWithResponses, error) {
	cfg := ClientConfig{}
	for _, op := range ops {
		op(&cfg)
	}
	url := getURL(addr)
	if cfg.skipVerify {
		if cfg.tlsConfig == nil {
			cfg.tlsConfig = &tls.Config{}
		}
		cfg.tlsConfig.InsecureSkipVerify = true
	}
	customize := func(client *nbi.Client) error {
		if cfg.tlsConfig != nil {
			client.Client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: cfg.tlsConfig,
				},
			}
		}
		if cfg.bearerToken != "" {
			addToken := func(ctx context.Context, req *http.Request) error {
				req.Header.Add("Authorization", "Bearer "+cfg.bearerToken)
				return nil
			}
			client.RequestEditors = append(client.RequestEditors, addToken)
		}
		return nil
	}
	return nbi.NewClientWithResponses(url, customize)
}

type ResponseStatus interface {
	// StatusCode returns the http status code from the response
	StatusCode() int
	// Body returns the response data
	GetBody() []byte
}

func checkForAPIErr(desc string, resp ResponseStatus, err error, okStatus ...int) *APIErr {
	if err != nil {
		return wrapAPIErr(desc, 0, err)
	}
	status := resp.StatusCode()
	if len(okStatus) == 0 {
		okStatus = []int{http.StatusOK}
	}
	for _, st := range okStatus {
		if st == status {
			// no failure
			return nil
		}
	}
	return readAPIErr(desc, status, resp.GetBody())
}

func wrapAPIErr(desc string, status int, err error) *APIErr {
	return &APIErr{
		Desc:   desc,
		Status: status,
		Err:    err.Error(),
	}
}

func readAPIErr(desc string, status int, body []byte) *APIErr {
	info := nbi.ErrorInfo{}
	errMsg := ""
	if len(body) > 0 {
		// NBI should have all failed responses as ErrorInfo
		err := json.Unmarshal(body, &info)
		if err != nil {
			errMsg = string(body)
		} else {
			errMsg = info.Message
		}
	}
	return &APIErr{
		Desc:   desc,
		Status: status,
		Err:    errMsg,
	}
}
