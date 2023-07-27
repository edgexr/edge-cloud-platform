package accessvars

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

// CRMAccessKeys are used by on-site CRMs to authenticate
// with the Controller's accesskey API endpoint.
// Secondary keys are used for a second CRM in HA mode.
type CRMAccessKeys struct {
	PublicPEM           string
	PrivatePEM          string
	SecondaryPublicPEM  string
	SecondaryPrivatePEM string
}

func getCloudletCRMAccessKeysPath(region string, cloudlet *edgeproto.Cloudlet) string {
	return fmt.Sprintf("secret/data/%s/cloudlet/%s/%s/accesskeys", region, cloudlet.Key.Organization, cloudlet.Key.Name)
}

func SaveCRMAccessKeys(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, accessKeys *CRMAccessKeys) error {
	path := getCloudletCRMAccessKeysPath(region, cloudlet)
	return vault.PutData(vaultConfig, path, accessKeys)
}

func DeleteCRMAccessKeys(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config) error {
	path := getCloudletCRMAccessKeysPath(region, cloudlet)
	return vault.DeleteData(vaultConfig, path)
}

func GetCRMAccessKeys(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config) (*CRMAccessKeys, error) {
	path := getCloudletCRMAccessKeysPath(region, cloudlet)
	keys := CRMAccessKeys{}
	err := vault.GetData(vaultConfig, path, 0, &keys)
	return &keys, err
}
