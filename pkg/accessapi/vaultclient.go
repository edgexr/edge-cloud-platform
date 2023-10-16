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

package accessapi

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/chefauth"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/gcs"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

// VaultClient implements platform.AccessApi for access from the Controller
// directly to Vault. In some cases it may require loading the platform
// specific plugin.
// VaultClient should only be used in the context of the Controller.
type VaultClient struct {
	cloudlet            *edgeproto.Cloudlet
	vaultConfig         *vault.Config
	region              string
	dnsMgr              *dnsmgmt.DNSMgr
	cloudletNodeHandler CloudletNodeHandler
}

type CloudletNodeHandler interface {
	CreateCloudletNodeReq(ctx context.Context, node *edgeproto.CloudletNode) (string, error)
	DeleteCloudletNodeReq(ctx context.Context, key *edgeproto.CloudletNodeKey) error
}

func NewVaultClient(cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, cloudletNodeHandler CloudletNodeHandler, region string, dnsZones string) *VaultClient {
	return &VaultClient{
		cloudlet:            cloudlet,
		vaultConfig:         vaultConfig,
		region:              region,
		dnsMgr:              dnsmgmt.NewDNSMgr(vaultConfig, strings.Split(dnsZones, ",")),
		cloudletNodeHandler: cloudletNodeHandler,
	}
}

func NewVaultGlobalClient(vaultConfig *vault.Config) *VaultClient {
	return &VaultClient{
		vaultConfig: vaultConfig,
	}
}

func (s *VaultClient) GetCloudletAccessVars(ctx context.Context) (map[string]string, error) {
	if s.cloudlet == nil {
		return nil, fmt.Errorf("Missing cloudlet details")
	}
	return accessvars.GetCloudletAccessVars(ctx, s.region, s.cloudlet, s.vaultConfig)
}

func (s *VaultClient) GetRegistryAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	return cloudcommon.GetRegistryAuth(ctx, imgUrl, cloudcommon.AllOrgs, s.vaultConfig)
}

func (s *VaultClient) GetRegistryImageAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	return cloudcommon.GetRegistryImageAuth(ctx, imgUrl, s.vaultConfig)
}

func (s *VaultClient) SignSSHKey(ctx context.Context, publicKey string) (string, error) {
	// Signed ssh keys should have a short valid time
	return vault.SignSSHKey(s.vaultConfig, publicKey)
}

func (s *VaultClient) GetSSHPublicKey(ctx context.Context) (string, error) {
	cmd := exec.Command("curl", "-s", fmt.Sprintf("%s/v1/ssh/public_key", s.vaultConfig.Addr))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get vault ssh cert: %s, %v", string(out), err)
	}
	if !strings.Contains(string(out), "ssh-rsa") {
		return "", fmt.Errorf("invalid vault ssh cert: %s", string(out))
	}
	return string(out), nil
}

func (s *VaultClient) GetOldSSHKey(ctx context.Context) (*vault.MEXKey, error) {
	// This is supported for upgrading old VMs only.
	vaultPath := "/secret/data/keys/id_rsa_mex"
	key := &vault.MEXKey{}
	err := vault.GetData(s.vaultConfig, vaultPath, 0, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get mex key for %s, %v", vaultPath, err)
	}
	return key, nil
}

// GetChefAuthKey is deprecated, it is kept for backwards compatibility
// with old crms
func (s *VaultClient) GetChefAuthKey(ctx context.Context) (*chefauth.ChefAuthKey, error) {
	// TODO: maintain a Cloudlet-specific API key
	auth, err := chefauth.GetChefAuthKeys(ctx, s.vaultConfig)
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func (s *VaultClient) CreateOrUpdateDNSRecord(ctx context.Context, name, rtype, content string, ttl int, proxy bool) error {
	// restrict the record types that CRM can make
	if rtype != dnsapi.RecordTypeA && rtype != dnsapi.RecordTypeAAAA && rtype != dnsapi.RecordTypeCNAME {
		return fmt.Errorf("record type %s not allowed", rtype)
	}
	// TODO: validate parameters are ok for this cloudlet
	return s.dnsMgr.CreateOrUpdateDNSRecord(ctx, name, rtype, content, ttl, proxy)
}

func (s *VaultClient) GetDNSRecords(ctx context.Context, fqdn string) ([]dnsapi.Record, error) {
	// TODO: validate parameters are ok for this cloudlet
	return s.dnsMgr.GetDNSRecords(ctx, fqdn)
}

func (s *VaultClient) DeleteDNSRecord(ctx context.Context, recordID string) error {
	// TODO: validate parameters are ok for this cloudlet
	return s.dnsMgr.DeleteDNSRecord(ctx, recordID)
}

func (s *VaultClient) GetSessionTokens(ctx context.Context, secretName string) (string, error) {
	return accessvars.GetCloudletTotpCode(ctx, s.region, s.cloudlet, s.vaultConfig, secretName)
}

func (s *VaultClient) GetPublicCert(ctx context.Context, commonName string) (*vault.PublicCert, error) {
	publicCert, err := vault.GetPublicCert(s.vaultConfig, commonName)
	if err != nil {
		return nil, err
	}
	return publicCert, nil
}

func (s *VaultClient) GetKafkaCreds(ctx context.Context) (*node.KafkaCreds, error) {
	path := node.GetKafkaVaultPath(s.region, s.cloudlet.Key.Name, s.cloudlet.Key.Organization)
	creds := node.KafkaCreds{}
	err := vault.GetData(s.vaultConfig, path, 0, &creds)
	if err != nil {
		return nil, fmt.Errorf("failed to get kafka credentials at %s, %v", path, err)
	}
	return &creds, nil
}

func (s *VaultClient) GetGCSCreds(ctx context.Context) ([]byte, error) {
	creds, err := gcs.GetGCSCreds(ctx, s.vaultConfig)
	if err != nil {
		return nil, err
	}
	return creds, nil
}

func (s *VaultClient) GetFederationAPIKey(ctx context.Context, fedKey *federationmgmt.FedKey) (*federationmgmt.ApiKey, error) {
	apiKey, err := federationmgmt.GetFederationAPIKey(ctx, s.vaultConfig, fedKey)
	if err != nil {
		return nil, err
	}
	return apiKey, nil
}

func (s *VaultClient) CreateCloudletNode(ctx context.Context, node *edgeproto.CloudletNode) (string, error) {
	if s.cloudletNodeHandler == nil {
		return "", fmt.Errorf("create cloudlet node not supported")
	}
	return s.cloudletNodeHandler.CreateCloudletNodeReq(ctx, node)
}

func (s *VaultClient) DeleteCloudletNode(ctx context.Context, nodeKey *edgeproto.CloudletNodeKey) error {
	if s.cloudletNodeHandler == nil {
		return fmt.Errorf("delete cloudlet node not supported")
	}
	return s.cloudletNodeHandler.DeleteCloudletNodeReq(ctx, nodeKey)
}
