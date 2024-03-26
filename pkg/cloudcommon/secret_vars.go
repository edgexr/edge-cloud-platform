package cloudcommon

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

const RedactedSecret = "***"

func getVaultAppSecretVarsPath(region string, appKey *edgeproto.AppKey) string {
	return fmt.Sprintf("/secret/data/%s/apps/%s/%s/%s/secretenvvars", region, appKey.Organization, appKey.Name, appKey.Version)
}

func RedactSecretVars(vars map[string]string) map[string]string {
	redacted := map[string]string{}
	for k := range vars {
		redacted[k] = RedactedSecret
	}
	return redacted
}

func SaveSecretVars(ctx context.Context, path string, vaultConfig *vault.Config, vars map[string]string) error {
	if len(vars) == 0 {
		return nil
	}
	log.SpanLog(ctx, log.DebugLevelApi, "SaveSecretVars", "path", path)
	return vault.PutData(vaultConfig, path, vars)
}

func GetSecretVars(ctx context.Context, path string, vaultConfig *vault.Config) (map[string]string, error) {
	vars := map[string]string{}
	err := vault.GetData(vaultConfig, path, 0, &vars)
	if err != nil && !vault.IsErrNoSecretsAtPath(err) {
		return vars, err
	}
	return vars, nil
}

func UpdateSecretVars(ctx context.Context, path string, vaultConfig *vault.Config, vars map[string]string, updateListAction string) (map[string]string, error) {
	updatedVars, err := GetSecretVars(ctx, path, vaultConfig)
	if err != nil {
		return nil, err
	}
	if updateListAction == util.UpdateListActionReplace {
		updatedVars = vars
	} else if updateListAction == util.UpdateListActionRemove {
		for k := range vars {
			delete(updatedVars, k)
		}
	} else { // default to add
		for k, v := range vars {
			updatedVars[k] = v
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "UpdateSecretVars", "path", path)
	err = SaveSecretVars(ctx, path, vaultConfig, updatedVars)
	return updatedVars, err
}

func DeleteSecretVars(ctx context.Context, path string, vaultConfig *vault.Config) error {
	log.SpanLog(ctx, log.DebugLevelApi, "DeleteSecretVars", "path", path)
	err := vault.DeleteData(vaultConfig, path)
	if err != nil && vault.IsErrNoSecretsAtPath(err) {
		err = nil
	}
	return err
}

// App-specific funcs

func SaveAppSecretVars(ctx context.Context, region string, appKey *edgeproto.AppKey, vaultConfig *vault.Config, vars map[string]string) error {
	path := getVaultAppSecretVarsPath(region, appKey)
	return SaveSecretVars(ctx, path, vaultConfig, vars)
}

func GetAppSecretVars(ctx context.Context, region string, appKey *edgeproto.AppKey, vaultConfig *vault.Config) (map[string]string, error) {
	path := getVaultAppSecretVarsPath(region, appKey)
	return GetSecretVars(ctx, path, vaultConfig)
}

func UpdateAppSecretVars(ctx context.Context, region string, appKey *edgeproto.AppKey, vaultConfig *vault.Config, vars map[string]string, updateListAction string) (map[string]string, error) {
	path := getVaultAppSecretVarsPath(region, appKey)
	return UpdateSecretVars(ctx, path, vaultConfig, vars, updateListAction)
}

func DeleteAppSecretVars(ctx context.Context, region string, appKey *edgeproto.AppKey, vaultConfig *vault.Config) error {
	path := getVaultAppSecretVarsPath(region, appKey)
	return DeleteSecretVars(ctx, path, vaultConfig)
}
