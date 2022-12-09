package orm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

func vmRegistryEnsureApiKey(ctx context.Context, username string) error {
	auth, err := cloudcommon.GetRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, serverConfig.vaultConfig)
	if err != nil {
		return err
	}
	if auth.AuthType != cloudcommon.NoAuth {
		// already exists
		log.SpanLog(ctx, log.DebugLevelApi, "vm registry api key already exists")
		return nil
	}
	// Create api key to access artifacts.
	// Unfortunately CRM needs to delete ovf files, otherwise
	// it would be better to have a separate key for CRM that
	// can only download (and upload converted qcow2->vmdk).
	apiKeyReq := &ormapi.CreateUserApiKey{
		UserApiKey: ormapi.UserApiKey{
			Description: "admin artifact api key",
		},
		Permissions: []ormapi.RolePerm{{
			Resource: ResourceArtifacts,
			Action:   ActionManage,
		}},
	}
	log.SpanLog(ctx, log.DebugLevelApi, "creating vm registry api key")
	err = createUserApiKeyInternal(ctx, username, apiKeyReq)
	if err != nil {
		return err
	}
	auth = &cloudcommon.RegistryAuth{
		AuthType: cloudcommon.BasicAuth,
		Username: apiKeyReq.Id,
		Password: apiKeyReq.ApiKey,
	}
	// will not overwrite existing secret, avoids race
	// condition with another process.
	err = cloudcommon.PutRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, auth, serverConfig.vaultConfig, 0)
	if vault.IsCheckAndSetError(err) {
		err = nil
		// already exists
		undoErr := deleteUserApiKeyInternal(ctx, username, apiKeyReq.Id)
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo vm registry api key failed", "err", undoErr)
		}
	}
	return err
}
