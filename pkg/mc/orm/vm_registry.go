package orm

import (
	"context"
	fmt "fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/google/uuid"
)

const vmRegOrgValidDur = 43800 * time.Hour // 5 years

func getVmRegAdminAuth(ctx context.Context) (*cloudcommon.RegistryAuth, error) {
	return cloudcommon.GetRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, serverConfig.vaultConfig)
}

func vmRegistryEnsureApiKey(ctx context.Context, username string) error {
	auth, err := getVmRegAdminAuth(ctx)
	if err != nil {
		return err
	}
	if auth.AuthType == cloudcommon.BasicAuth {
		// already exists, check that it's set up properly.
		db := loggedDB(ctx)
		apiKey := ormapi.UserApiKey{
			Id: auth.Username,
		}
		res := db.Where(&apiKey).First(&apiKey)
		if res.RecordNotFound() {
			log.SpanLog(ctx, log.DebugLevelApi, "vm registry api key in Vault but not in MC, will create MC api key")
			// fallthrough to create api key
		} else if err == nil {
			// verify password
			matches, err := ormutil.PasswordMatches(auth.Password, apiKey.ApiKeyHash, apiKey.Salt, apiKey.Iter)
			if err == nil && matches {
				log.SpanLog(ctx, log.DebugLevelApi, "vm registry api key verified")
				return nil
			}
			log.SpanLog(ctx, log.DebugLevelApi, "vm registry api key authentication failed, syncing password to Vault's record")
			hash, salt, iter := ormutil.NewPasshash(auth.Password)
			apiKey.ApiKeyHash = hash
			apiKey.Salt = salt
			apiKey.Iter = iter
			err = db.Save(&apiKey).Error
			if err != nil {
				return fmt.Errorf("failed to save updated vm-registry apikey %s", apiKey.Id)
			}
			// ensure correct perimissions too
			keyRole := getApiKeyRoleName(apiKey.Id)
			params := []string{
				keyRole,
				ResourceArtifacts,
				ActionManage,
			}
			err = enforcer.AddPolicy(ctx, params...)
			if err != nil {
				return fmt.Errorf("failed to set artifact manage enforcer policy %v: %s", params, err)
			}
			params = []string{
				keyRole,
				ResourceArtifacts,
				ActionView,
			}
			err = enforcer.AddPolicy(ctx, params...)
			if err != nil {
				return fmt.Errorf("failed to set artifact view enforcer policy %v: %s", params, err)
			}
		} else {
			return fmt.Errorf("error looking up vm registry apikey %s", auth.Username)
		}
	} else if auth.AuthType != cloudcommon.NoAuth {
		return fmt.Errorf("Invalid vm registry auth type %s, want %s", auth.AuthType, cloudcommon.BasicAuth)
	} else {
		// key not present in Vault, create a new one.
		// We push to Vault first, as that push can be synchronized via
		// the set and check to avoid race conditions with another MC
		// also trying to create the key at the same time.
		auth.AuthType = cloudcommon.BasicAuth
		auth.Username = uuid.New().String()
		auth.Password = uuid.New().String()
		// will not overwrite existing secret
		err = cloudcommon.PutRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, auth, serverConfig.vaultConfig, 0)
		if vault.IsCheckAndSetError(err) {
			// the other process will create the apikey
			log.SpanLog(ctx, log.DebugLevelApi, "conflict creating apikey, allow other process to proceed", "registry", serverConfig.VmRegistryAddr)
			return nil
		}
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
	err = createUserApiKeyInternal(ctx, username, auth.Username, auth.Password, apiKeyReq)
	if err != nil {
		return err
	}
	return nil
}

func vmRegistryCreateOrgPullKey(ctx context.Context, org, orgType string) {
	if orgType == OrgTypeOperator {
		return
	}
	auth, err := getVmRegAdminAuth(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "vm-registry failed to get admin auth for new org create", "err", err)
		vmRegistrySync.NeedsSync()
		return
	}
	err = vmRegistryEnsurePullKey(ctx, org, auth.Username)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "vm-registry failed to create org pull key", "org", org, "err", err)
		vmRegistrySync.NeedsSync()
	}
}

// Create a JWT token for pulling VM images. It is restricted to the org.
func vmRegistryEnsurePullKey(ctx context.Context, org, username string) error {
	// Since it's just a JWT token, we don't care if it already
	// exists, just overwrite it with a new one.
	user := ormapi.User{
		Name: username,
	}
	// config is only used for durations, which we override
	config := &ormapi.Config{}
	cookie, err := GenerateCookie(&user, "", serverConfig.HTTPCookieDomain, config, WithOrgRestriction(org), WithActionRestriction(ActionView), WithValidDuration(vmRegOrgValidDur))
	if err != nil {
		return err
	}
	auth := cloudcommon.RegistryAuth{
		AuthType: cloudcommon.TokenAuth,
		Username: user.Name,
		Token:    cookie.Value,
	}
	return cloudcommon.PutRegistryAuth(ctx, serverConfig.VmRegistryAddr, org, &auth, serverConfig.vaultConfig, -1)
}

func vmRegistryGetPullKey(ctx context.Context, org string) (*cloudcommon.RegistryAuth, error) {
	return cloudcommon.GetRegistryAuth(ctx, serverConfig.VmRegistryAddr, org, serverConfig.vaultConfig)
}

func vmRegistryDeletePullKey(ctx context.Context, org, orgType string) error {
	// TODO: MC does not have sufficient vault perms for this
	// yet, it needs to be able to delete the metadata path.
	if true {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
	return cloudcommon.DeleteRegistryAuth(ctx, serverConfig.VmRegistryAddr, org, serverConfig.vaultConfig)
}
