package orm

import (
	"context"
	fmt "fmt"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/google/uuid"
)

var vmRegCookie *http.Cookie

func vmRegistryEnsureApiKey(ctx context.Context, username string) error {
	auth, err := cloudcommon.GetRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, serverConfig.vaultConfig)
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

// Used by federation to interact with vm registry
func getVmRegistryCookie(ctx context.Context) (*http.Cookie, error) {
	if vmRegCookie != nil {
		// verify that it's still valid
		verifyClaims := ormutil.UserClaims{}
		token, err := Jwks.VerifyCookie(vmRegCookie.Value, &verifyClaims)
		if err == nil && token.Valid {
			return vmRegCookie, nil
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Generating new vm registry cookie")
	auth, err := cloudcommon.GetRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, serverConfig.vaultConfig)
	if err != nil {
		return nil, err
	}
	if auth.Username == "" {
		return nil, fmt.Errorf("Username not found for VM Registry auth")
	}
	user := ormapi.User{
		Name: auth.Username,
	}
	config, err := getConfig(ctx)
	if err != nil {
		return nil, err
	}
	cookie, err := GenerateCookie(&user, "", serverConfig.HTTPCookieDomain, config)
	if err != nil {
		return nil, err
	}
	vmRegCookie = cookie
	return vmRegCookie, nil
}
