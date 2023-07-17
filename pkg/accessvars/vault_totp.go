package accessvars

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

const (
	TotpSecretMount = "totp"
	TotpTokenName   = "code"
)

type TotpPathType string

const (
	TotpKeysPath TotpPathType = "keys"
	TotpCodePath TotpPathType = "code"
)

func getCloudletTotpPath(region string, pathType TotpPathType, cloudlet *edgeproto.Cloudlet, secretName string) string {
	name := cloudlet.PhysicalName
	if name == "" {
		name = cloudlet.Key.Name
	}
	// Vault doesn't support a hierarchical namespace for keys.
	// To avoid aliasing, we base64 encode the cloudlet path.
	cloudletPath := fmt.Sprintf("cloudlet/%s/%s/%s", cloudlet.Key.Organization, name, secretName)
	totpName := base64.StdEncoding.EncodeToString([]byte(cloudletPath))
	return region + "/" + TotpSecretMount + "/" + string(pathType) + "/" + totpName
}

func SaveCloudletTotpSecret(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, secretName, secretVal string) error {
	path := getCloudletTotpPath(region, TotpKeysPath, cloudlet, secretName)
	client, err := vaultConfig.Login()
	if err != nil {
		return err
	}
	// parameters: see https://developer.hashicorp.com/vault/api-docs/secret/totp
	req := map[string]interface{}{
		"key":    secretVal,
		"digits": 6,
	}
	_, err = client.Logical().Write(path, req)
	log.SpanLog(ctx, log.DebugLevelApi, "SaveCloudletTotp secret", "cloudlet", cloudlet.Key, "secretName", secretName, "path", path, "err", err)
	return err
}

func DeleteCloudletTotpSecret(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, secretName string) error {
	path := getCloudletTotpPath(region, TotpKeysPath, cloudlet, secretName)
	client, err := vaultConfig.Login()
	if err != nil {
		return err
	}
	_, err = client.Logical().Delete(path)
	log.SpanLog(ctx, log.DebugLevelApi, "DeleteCloudletTotp secret", "cloudlet", cloudlet.Key, "secretName", secretName, "path", path, "err", err)
	return err
}

func GetCloudletTotpCode(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, secretName string) (string, error) {
	path := getCloudletTotpPath(region, TotpCodePath, cloudlet, secretName)
	client, err := vaultConfig.Login()
	if err != nil {
		return "", err
	}
	secret, err := client.Logical().Read(path)
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("No data returned from Vault for totp code")
	}
	code, ok := secret.Data[TotpTokenName]
	if !ok {
		return "", fmt.Errorf("No code returned in Vault data for totp")
	}
	codeStr, ok := code.(string)
	if !ok {
		return "", fmt.Errorf("Code returned from Vault is not a string")
	}
	return codeStr, nil
}
