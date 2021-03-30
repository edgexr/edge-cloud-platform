package vcd

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/vault"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IdToken      string `json:"id_token"`
}

const ClientId = "client_id"
const ClientSecret = "client_secret"
const GrantType = "grant_type"
const Scope = "scope"

const GrantTypeCert = "CERT"
const ScopeOpenId = "openid"
const ContentFormUrlEncoded = "application/x-www-form-urlencoded"

// GetCredsFromVaultForSimulator is for use by AGW and SGW simulators which do not
// use the AccessApi functionality from controller
func (v *VcdPlatform) getVcdVarsFromVaultForSimulator(ctx context.Context, region, orgName, physName, vaultAddr string) error {
	path := fmt.Sprintf("/secret/data/%s/cloudlet/vcd/%s/%s/vcd.json", region, orgName, physName)
	vaultConfig, err := vault.BestConfig(vaultAddr)
	if err != nil {
		return fmt.Errorf("Unable to get vault config - %v", err)
	}
	v.vcdVars, err = infracommon.GetEnvVarsFromVault(ctx, vaultConfig, path)
	if err != nil {
		return fmt.Errorf("Unable to get vars from vault: %s -  %v", vaultAddr, err)
	}
	return nil
}

func (v *VcdPlatform) PopulateCredsForSimulator(ctx context.Context, region, orgName, physName, vaultAddr string) error {
	err := v.getVcdVarsFromVaultForSimulator(ctx, region, orgName, physName, vaultAddr)
	if err != nil {
		return err
	}
	err = v.PopulateOrgLoginCredsFromVcdVars(ctx)
	if err != nil {
		return err
	}
	// additional checks because these are optional in the platform
	if v.Creds.OauthClientId == "" {
		return fmt.Errorf("VCD_OAUTH_CLIENT_ID not found")
	}
	if v.Creds.OauthClientSecret == "" {
		return fmt.Errorf("VCD_OAUTH_CLIENT_SECRET not found")
	}
	if v.Creds.ClientTlsCert == "" {
		return fmt.Errorf("VCD_CLIENT_TLS_CERT not found")
	}
	if v.Creds.ClientTlsKey == "" {
		return fmt.Errorf("VCD_CLIENT_TLS_KEY not found")
	}
	return nil
}
