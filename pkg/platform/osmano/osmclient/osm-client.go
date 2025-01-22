// Copyright 2025 EdgeXR, Inc
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

// Package osmclient provides client API functions for
// OpenSourceMano APIs
package osmclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmapi"
)

type OSMClient struct {
	AccessVars     map[string]string
	Properties     *infracommon.InfraProperties
	client         *osmapi.ClientWithResponses
	token          *osmapi.TokenInfo
	tokenExpiresAt *time.Time
}

func (s *OSMClient) Init(accessVars map[string]string, properties *infracommon.InfraProperties) error {
	s.AccessVars = accessVars
	s.Properties = properties

	// set up OSM API client
	skipVerify := false
	if val, _ := properties.GetValue(OSM_SKIPVERIFY); val != "" {
		skipVerify = true
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
	}
	addToken := func(ctx context.Context, req *http.Request) error {
		if s.token != nil && s.token.Id != nil {
			req.Header.Add("Authorization", "Bearer "+*s.token.Id)
		}
		req.Header.Add("Accept", "application/json")
		return nil
	}
	apiURL, ok := accessVars[OSM_URL]
	if !ok || apiURL == "" {
		return fmt.Errorf("missing %s access var", OSM_URL)
	}

	auditedClient := &log.HTTPRequestDoerAuditor{}
	auditedClient.Doer = httpClient
	client, err := osmapi.NewClientWithResponses(apiURL,
		osmapi.WithHTTPClient(auditedClient),
		osmapi.WithRequestEditorFn(addToken),
	)
	if err != nil {
		return err
	}
	s.client = client
	return nil
}

func (s *OSMClient) GetClient(ctx context.Context) (*osmapi.ClientWithResponses, error) {
	err := s.ensureValidToken(ctx)
	if err != nil {
		return nil, err
	}
	return s.client, nil
}

func (s *OSMClient) ensureValidToken(ctx context.Context) error {
	if s.token != nil {
		if s.tokenExpiresAt == nil || time.Now().Before(*s.tokenExpiresAt) {
			// token is still valid or does not expire
			return nil
		}
		// fallthrough to get token
	}
	if s.client == nil {
		return fmt.Errorf("ensure token failure, client not initialized yet")
	}
	if s.AccessVars == nil {
		return fmt.Errorf("ensure token failure, access vars not initialized yet")
	}
	req := osmapi.CreateTokenRequest{
		Username: s.AccessVars[OSM_USERNAME],
		Password: s.AccessVars[OSM_PASSWORD],
	}
	resp, err := s.client.CreateTokenWithResponse(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get token, %s", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed token request (%d), %s", resp.StatusCode(), string(resp.Body))
	}
	token := osmapi.TokenInfo{}
	err = json.Unmarshal(resp.Body, &token)
	if err != nil {
		return fmt.Errorf("failed to unmarshal token response, %s", err)
	}
	if token.Id == nil {
		return fmt.Errorf("ensure token failed, token response missing ID")
	}
	if token.Expires != nil {
		sec := int64(*token.Expires)
		nanosec := int64((*token.Expires - float32(sec)) * 1e9)
		expiresAt := time.Unix(sec, nanosec)
		s.tokenExpiresAt = &expiresAt
	} else {
		s.tokenExpiresAt = nil
	}
	s.token = &token
	return nil
}

// FromEnv pulls access vars and properties from the environment,
// for unit testing.
func FromEnv() (map[string]string, *infracommon.InfraProperties) {
	accessVars := make(map[string]string)
	properties := &infracommon.InfraProperties{
		Properties: make(map[string]*edgeproto.PropertyInfo),
	}
	properties.SetProperties(Props)
	properties.SetValue(OSM_REGION, os.Getenv(OSM_REGION))
	properties.SetValue(OSM_VIM_ACCOUNT, os.Getenv(OSM_VIM_ACCOUNT))
	properties.SetValue(OSM_RESOURCE_GROUP, os.Getenv(OSM_RESOURCE_GROUP))
	properties.SetValue(OSM_SKIPVERIFY, os.Getenv(OSM_SKIPVERIFY))
	accessVars[OSM_USERNAME] = os.Getenv(OSM_USERNAME)
	accessVars[OSM_PASSWORD] = os.Getenv(OSM_PASSWORD)
	accessVars[OSM_URL] = os.Getenv(OSM_URL)
	return accessVars, properties
}

func readResp(desc string, resp *http.Response, err error) (int, []byte, error) {
	if err != nil {
		return 0, nil, fmt.Errorf("failed to %s, %s", desc, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("failed to %s response, %s", desc, err)
	}
	return resp.StatusCode, body, nil
}

func parseResp(desc string, body []byte, respObj any) error {
	if respObj != nil {
		err := json.Unmarshal(body, respObj)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s response, %s for %s", desc, err, string(body))
		}
	}
	return nil
}

func mustResp(desc string, resp *http.Response, err error, wantCode int, respObj any) error {
	status, body, err := readResp(desc, resp, err)
	if err != nil {
		return err
	}
	if status != wantCode {
		return fmt.Errorf("failed to %s (%d), %s", desc, resp.StatusCode, string(body))
	}
	return parseResp(desc, body, respObj)
}

func NameSanitize(clusterName string) string {
	clusterName = strings.NewReplacer(".", "").Replace(clusterName)
	return clusterName
}
