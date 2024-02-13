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
	"sort"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

func getCloudletAccessVarsPath(region string, cloudlet *edgeproto.Cloudlet) string {
	name := cloudlet.PhysicalName
	if name == "" {
		name = cloudlet.Key.Name
	}
	return fmt.Sprintf("secret/data/%s/cloudlet/%s/%s/accessvars", region, cloudlet.Key.Organization, name)
}

func SaveCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, accessVars map[string]string, props map[string]*edgeproto.PropertyInfo) error {
	// split vars into regular secrets and totp secrets
	vars := map[string]string{}
	totps := map[string]string{}
	if props == nil {
		vars = accessVars
	} else {
		for k, v := range accessVars {
			if p, found := props[k]; found && p.TotpSecret {
				totps[k] = v
			} else {
				vars[k] = v
			}
		}
	}
	if len(vars) > 0 {
		// save vars
		path := getCloudletAccessVarsPath(region, cloudlet)
		log.SpanLog(ctx, log.DebugLevelApi, "SaveCloudletAccessVars", "path", path)
		err := vault.PutData(vaultConfig, path, vars)
		if err != nil {
			return err
		}
	}
	if len(totps) > 0 {
		// write totp secrets to Vault totp engine
		for k, v := range totps {
			err := SaveCloudletTotpSecret(ctx, region, cloudlet, vaultConfig, k, v)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func GetCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config) (map[string]string, error) {
	path := getCloudletAccessVarsPath(region, cloudlet)
	vars := map[string]string{}
	err := vault.GetData(vaultConfig, path, 0, &vars)
	return vars, err
}

func UpdateCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, accessVars map[string]string, props map[string]*edgeproto.PropertyInfo) error {
	updatedVars, err := GetCloudletAccessVars(ctx, region, cloudlet, vaultConfig)
	if err != nil {
		return err
	}
	for k, v := range accessVars {
		updatedVars[k] = v
	}
	return SaveCloudletAccessVars(ctx, region, cloudlet, vaultConfig, updatedVars, props)
}

func DeleteCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config) error {
	path := getCloudletAccessVarsPath(region, cloudlet)
	log.SpanLog(ctx, log.DebugLevelApi, "DeleteCloudletAccessVars", "path", path)
	return vault.DeleteData(vaultConfig, path)
}

func ValidateAccessVars(accessVars map[string]string, props map[string]*edgeproto.PropertyInfo) error {
	invalid := []string{}
	for key := range accessVars {
		if _, ok := props[key]; !ok {
			invalid = append(invalid, key)
		}
	}
	if len(invalid) > 0 {
		validVars := []string{}
		for key := range props {
			validVars = append(validVars, key)
		}
		sort.Strings(invalid)
		sort.Strings(validVars)
		return fmt.Errorf("Invalid access vars %s, valid vars are %s", strings.Join(invalid, ", "), strings.Join(validVars, ", "))
	}
	notFound := []string{}
	for key, prop := range props {
		if prop.Mandatory {
			if _, found := accessVars[key]; !found {
				notFound = append(notFound, key)
			}
		}
	}
	if len(notFound) > 0 {
		sort.Strings(notFound)
		return fmt.Errorf("Missing required access vars %s", strings.Join(notFound, ", "))
	}
	return nil
}
