// Copyright 2025 EdgeXR, Inc
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

package cloudcommon

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

type AppRegAuth struct {
	Username    string
	Credentials string
}

func getAppRegistryAuthPath(region string, key edgeproto.AppKey) string {
	return fmt.Sprintf("secret/data/%s/app/%s/%s/%s/regauth", region, key.Organization, key.Name, key.Version)
}

func SaveAppRegistryAuth(ctx context.Context, region string, key edgeproto.AppKey, vaultConfig *vault.Config, auth *AppRegAuth) error {
	path := getAppRegistryAuthPath(region, key)
	log.SpanLog(ctx, log.DebugLevelApi, "save app registry auth", "path", path)
	return vault.PutData(vaultConfig, path, auth)
}

func DeleteAppRegistryAuth(ctx context.Context, region string, key edgeproto.AppKey, vaultConfig *vault.Config) error {
	path := getAppRegistryAuthPath(region, key)
	log.SpanLog(ctx, log.DebugLevelApi, "delete app registry auth", "path", path)
	return vault.DeleteData(vaultConfig, path)
}

func GetAppRegistryAuth(ctx context.Context, region string, key edgeproto.AppKey, vaultConfig *vault.Config) (*AppRegAuth, error) {
	path := getAppRegistryAuthPath(region, key)
	auth := AppRegAuth{}
	err := vault.GetData(vaultConfig, path, 0, &auth)
	log.SpanLog(ctx, log.DebugLevelApi, "get app registry auth", "path", path, "err", err)
	return &auth, err
}
