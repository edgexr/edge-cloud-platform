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
