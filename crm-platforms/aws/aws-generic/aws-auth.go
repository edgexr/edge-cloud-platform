package awsgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

const SessionTokenDurationSecs = 60 * 60 * 24 // 24 hours
const AwsSessionTokenRefreshInterval = 12 * time.Hour

type AwsSessionCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

type AwsSessionData struct {
	Credentials AwsSessionCredentials
}

// GetAwsSessionToken gets a totp code from the vault and then gets an AWS session token
func (a *AwsGenericPlatform) GetAwsSessionToken(ctx context.Context, vaultConfig *vault.Config) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAwsSessionToken")

	user, err := a.GetUserAccountIdFromArn(ctx, a.GetAwsUserArn())
	if err != nil {
		return err
	}
	code, err := a.GetAwsTotpToken(ctx, vaultConfig, user)
	if err != nil {
		return err
	}
	return a.GetAwsSessionTokenWithCode(ctx, code)
}

// GetAwsTotpToken gets a totp token from the vault
func (a *AwsGenericPlatform) GetAwsTotpToken(ctx context.Context, vaultConfig *vault.Config, account string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAwsTotpToken", "account", account)
	path := "totp/code/aws-" + account
	client, err := vaultConfig.Login()
	if err != nil {
		return "", err
	}
	vdat, err := vault.GetKV(client, path, 0)
	if err != nil {
		return "", err
	}
	code, ok := vdat["code"]
	if !ok {
		return "", fmt.Errorf("no totp code received from vault")
	}
	return code.(string), nil
}

// GetAwsSessionTokenWithCode uses the provided code to get session token details from AWS
func (a *AwsGenericPlatform) GetAwsSessionTokenWithCode(ctx context.Context, code string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAwsSessionTokenWithCode", "code", code)
	arn := a.GetAwsUserArn()
	mfaSerial := strings.Replace(arn, ":user/", ":mfa/", 1)
	out, err := a.TimedAwsCommand(ctx, AwsCredentialsAccount, "aws",
		"sts",
		"get-session-token",
		"--serial-number", mfaSerial,
		"--token-code", code,
		"--duration-seconds", fmt.Sprintf("%d", SessionTokenDurationSecs))

	if err != nil {
		return fmt.Errorf("Error in get-session-token: %s - %v", string(out), err)
	}
	var sessionData AwsSessionData
	err = json.Unmarshal(out, &sessionData)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws get-session-token unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	// save the session vars
	a.SessionAccessVars = make(map[string]string)
	a.SessionAccessVars["AWS_ACCESS_KEY_ID"] = sessionData.Credentials.AccessKeyId
	a.SessionAccessVars["AWS_SECRET_ACCESS_KEY"] = sessionData.Credentials.SecretAccessKey
	a.SessionAccessVars["AWS_SESSION_TOKEN"] = sessionData.Credentials.SessionToken
	a.AccountAccessVars["AWS_REGION"] = a.GetAwsRegion()
	return nil
}

// RefreshAwsSessionToken periodically gets a new session token
func (a *AwsGenericPlatform) RefreshAwsSessionToken(pfconfig *pf.PlatformConfig, vaultConfig *vault.Config) {
	interval := AwsSessionTokenRefreshInterval
	for {
		select {
		case <-time.After(interval):
		}
		span := log.StartSpan(log.DebugLevelInfra, "refresh aws session token")
		ctx := log.ContextWithSpan(context.Background(), span)
		err := a.GetAwsSessionToken(ctx, vaultConfig)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "refresh aws session error", "err", err)
			// retry again soon
			interval = time.Hour
		} else {
			interval = AwsSessionTokenRefreshInterval
		}
		span.Finish()
	}
}

func (a *AwsGenericPlatform) GetAwsAccountAccessVars(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAwsAccountAccessVars", "key", key)

	vaultPath := AwsDefaultVaultPath
	if key.Organization != "aws" {
		// this is not a public cloud aws cloudlet, use the operator specific path
		vaultPath = fmt.Sprintf("/secret/data/%s/cloudlet/%s/%s/%s/%s", region, "aws", key.Organization, physicalName, "credentials")
	}
	envData := &infracommon.VaultEnvData{}
	err := vault.GetData(vaultConfig, vaultPath, 0, envData)
	if err != nil {
		if strings.Contains(err.Error(), "no secrets") {
			return fmt.Errorf("Failed to source access variables as '%s/%s' "+
				"does not exist in secure secrets storage (Vault)",
				key.Organization, physicalName)
		}
		return fmt.Errorf("Failed to source access variables from %s, %s: %v", vaultConfig.Addr, vaultPath, err)
	}
	a.AccountAccessVars = make(map[string]string)
	for _, envData := range envData.Env {
		a.AccountAccessVars[envData.Name] = envData.Value
	}
	a.AccountAccessVars["AWS_REGION"] = a.GetAwsRegion()
	return nil
}
