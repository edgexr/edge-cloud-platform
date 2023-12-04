package accessapi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/chefauth"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"golang.org/x/crypto/ssh"
)

type TestHandler struct {
	AccessVars                map[string]string
	RegistryAuth              cloudcommon.RegistryAuth
	SSHSigningPublicKeyString string
	SSHSigningPublicKey       ssh.PublicKey
	SSHSigner                 ssh.Signer
}

func (s *TestHandler) GetCloudletAccessVars(ctx context.Context) (map[string]string, error) {
	return s.AccessVars, nil
}

func (s *TestHandler) GetRegistryAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	return &s.RegistryAuth, nil
}

func (s *TestHandler) GetRegistryImageAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	return &cloudcommon.RegistryAuth{}, nil
}

func (s *TestHandler) SignSSHKey(ctx context.Context, publicKey string) (string, error) {
	auth := vault.NewTokenAuth(os.Getenv("VAULT_TOKEN"))
	vaultConfig := vault.NewConfig(os.Getenv("VAULT_ADDR"), auth)
	return vault.SignSSHKey(vaultConfig, publicKey)
}

func (s *TestHandler) GetSSHPublicKey(ctx context.Context) (string, error) {
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

func (s *TestHandler) GetDNSRecords(ctx context.Context, fqdn string) ([]cloudflare.DNSRecord, error) {
	return []cloudflare.DNSRecord{}, nil
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

func (s *TestHandler) GetKafkaCreds(ctx context.Context) (*node.KafkaCreds, error) {
	return &node.KafkaCreds{}, nil
}

func (s *TestHandler) GetGCSCreds(ctx context.Context) ([]byte, error) {
	return []byte{}, nil
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
