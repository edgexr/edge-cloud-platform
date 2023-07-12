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

func SaveCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, accessVars map[string]string) error {
	path := getCloudletAccessVarsPath(region, cloudlet)
	log.SpanLog(ctx, log.DebugLevelApi, "SaveCloudletAccessVars", "path", path)
	return vault.PutData(vaultConfig, path, accessVars)
}

func GetCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config) (map[string]string, error) {
	path := getCloudletAccessVarsPath(region, cloudlet)
	vars := map[string]string{}
	err := vault.GetData(vaultConfig, path, 0, &vars)
	return vars, err
}

func UpdateCloudletAccessVars(ctx context.Context, region string, cloudlet *edgeproto.Cloudlet, vaultConfig *vault.Config, accessVars map[string]string) error {
	updatedVars, err := GetCloudletAccessVars(ctx, region, cloudlet, vaultConfig)
	if err != nil {
		return err
	}
	for k, v := range accessVars {
		updatedVars[k] = v
	}
	return SaveCloudletAccessVars(ctx, region, cloudlet, vaultConfig, updatedVars)
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
