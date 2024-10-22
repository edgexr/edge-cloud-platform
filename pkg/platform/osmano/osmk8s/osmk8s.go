// Copyright 2024 EdgeXR, Inc
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

// Package osmano provides the translation layer for using the
// Open Source Mano platform as a Kubernetes cluster provider
// (https://osm.etsi.org/).
package osmk8s

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/managedk8s"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmapi"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

type Platform struct {
	properties     *infracommon.InfraProperties
	accessVars     map[string]string
	client         *osmapi.ClientWithResponses
	token          *osmapi.TokenInfo
	tokenExpiresAt *time.Time
}

func NewPlatform() platform.Platform {
	return &managedk8s.ManagedK8sPlatform{
		Provider: &Platform{},
	}
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeOSMK8S,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		AccessVars:                    AccessVarProps,
		Properties:                    Props,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		RequiresCrmOffEdge:            true,
	}
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	// OSM has no way to list resource limits
	// OSM has no way to list flavors
	return nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *Platform) Login(ctx context.Context) error {
	_, err := s.getClient(ctx)
	return err
}

func (s *Platform) NameSanitize(clusterName string) string {
	clusterName = strings.NewReplacer(".", "").Replace(clusterName)
	return clusterName
}

func (s *Platform) SetProperties(props *infracommon.InfraProperties) error {
	s.properties = props
	return nil
}

func (s *Platform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *Platform) getClient(ctx context.Context) (*osmapi.ClientWithResponses, error) {
	if s.client != nil {
		if err := s.ensureValidToken(ctx); err != nil {
			return nil, err
		}
		return s.client, nil
	}

	skipVerify := false
	if val, _ := s.properties.GetValue(OSM_SKIPVERIFY); val != "" {
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
	auditedClient := &log.HTTPRequestDoerAuditor{}
	auditedClient.Doer = httpClient
	client, err := osmapi.NewClientWithResponses(s.getAPIURL(),
		osmapi.WithHTTPClient(auditedClient),
		osmapi.WithRequestEditorFn(addToken),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup osmapi client, %s", err)
	}
	s.client = client

	err = s.ensureValidToken(ctx)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *Platform) ensureValidToken(ctx context.Context) error {
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
	req := osmapi.CreateTokenRequest{
		Username: s.accessVars[OSM_USERNAME],
		Password: s.accessVars[OSM_PASSWORD],
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
