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

package accessapi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	dnsapi "github.com/edgexr/dnsproviders/api"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/chefauth"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

type TestHandler struct {
	AccessVars   map[string]string
	RegistryAuth cloudcommon.RegistryAuth
	SkipVault    bool
}

func (s *TestHandler) GetCloudletAccessVars(ctx context.Context) (map[string]string, error) {
	return s.AccessVars, nil
}

func (s *TestHandler) GetRegistryAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	return &s.RegistryAuth, nil
}

func (s *TestHandler) GetAppRegistryAuth(ctx context.Context, imgUrl string, appKey edgeproto.AppKey) (*cloudcommon.RegistryAuth, error) {
	return &s.RegistryAuth, nil
}

func (s *TestHandler) GetRegistryImageAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	return &cloudcommon.RegistryAuth{}, nil
}

func (s *TestHandler) SignSSHKey(ctx context.Context, publicKey string) (string, error) {
	if s.SkipVault {
		return "signedKey", nil
	}
	auth := vault.NewTokenAuth(os.Getenv("VAULT_TOKEN"))
	vaultConfig := vault.NewConfig(os.Getenv("VAULT_ADDR"), auth)
	return vault.SignSSHKey(vaultConfig, publicKey)
}

func (s *TestHandler) GetSSHPublicKey(ctx context.Context) (string, error) {
	if s.SkipVault {
		return "publicKey", nil
	}
	auth := vault.NewTokenAuth(os.Getenv("VAULT_TOKEN"))
	vaultConfig := vault.NewConfig(os.Getenv("VAULT_ADDR"), auth)
	cmd := exec.Command("curl", "-s", fmt.Sprintf("%s/v1/ssh/public_key", vaultConfig.Addr))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get vault ssh cert: %s, %v", string(out), err)
	}
	if !strings.Contains(string(out), "ssh-rsa") {
		return "", fmt.Errorf("invalid vault ssh cert: %s", string(out))
	}
	return string(out), nil
}

func (s *TestHandler) GetOldSSHKey(ctx context.Context) (*vault.MEXKey, error) {
	return &vault.MEXKey{}, nil
}

func (s *TestHandler) GetChefAuthKey(ctx context.Context) (*chefauth.ChefAuthKey, error) {
	return &chefauth.ChefAuthKey{}, nil
}

func (s *TestHandler) CreateOrUpdateDNSRecord(ctx context.Context, name, rtype, content string, ttl int, proxy bool) error {
	return nil
}

func (s *TestHandler) GetDNSRecords(ctx context.Context, fqdn string) ([]dnsapi.Record, error) {
	return []dnsapi.Record{}, nil
}

func (s *TestHandler) DeleteDNSRecord(ctx context.Context, recordID string) error {
	return nil
}

func (s *TestHandler) GetSessionTokens(ctx context.Context, secretName string) (string, error) {
	return "session-token", nil
}

func (s *TestHandler) GetPublicCert(ctx context.Context, commonName string) (*vault.PublicCert, error) {
	return &vault.PublicCert{}, nil
}

func (s *TestHandler) GetKafkaCreds(ctx context.Context) (*svcnode.KafkaCreds, error) {
	return &svcnode.KafkaCreds{}, nil
}

func (s *TestHandler) GetFederationAPIKey(ctx context.Context, fedKey *federationmgmt.FedKey) (*federationmgmt.ApiKey, error) {
	return &federationmgmt.ApiKey{}, nil
}

func (s *TestHandler) CreateCloudletNode(ctx context.Context, node *edgeproto.CloudletNode) (string, error) {
	return "cloudlet-node-key", nil
}

func (s *TestHandler) DeleteCloudletNode(ctx context.Context, nodeKey *edgeproto.CloudletNodeKey) error {
	return nil
}

func (s *TestHandler) GetAppSecretVars(ctx context.Context, appKey *edgeproto.AppKey) (map[string]string, error) {
	return map[string]string{}, nil
}

func (s *TestHandler) ReserveLoadBalancerIP(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) (*edgeproto.LoadBalancer, error) {
	return &edgeproto.LoadBalancer{}, nil
}

func (s *TestHandler) FreeLoadBalancerIP(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) error {
	return nil
}
