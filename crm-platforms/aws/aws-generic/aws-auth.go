package awsgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
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
	user, err := a.GetUserAccountIdFromArn(ctx, a.GetAwsUserArn())
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
	out, err := a.TimedAwsCommand(ctx, "aws",
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
	// now set envvars
	err = os.Setenv("AWS_ACCESS_KEY_ID", sessionData.Credentials.AccessKeyId)
	if err != nil {
		return err
	}
	err = os.Setenv("AWS_SECRET_ACCESS_KEY", sessionData.Credentials.SecretAccessKey)
	if err != nil {
		return err
	}
	err = os.Setenv("AWS_SESSION_TOKEN", sessionData.Credentials.SessionToken)
	if err != nil {
		return err
	}
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

		// save the old values in case we fail to get a new token
		oldAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		oldSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		oldSessionToken := os.Getenv("AWS_SESSION_TOKEN")
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("AWS_SECRET_ACCESS_KEY")
		os.Unsetenv("AWS_SESSION_TOKEN")

		// Call GetProviderSpecificProps which will reset the login credentials as we cannot use the
		// session credentials to get a session token
		_, err := a.GetProviderSpecificProps(ctx, pfconfig, vaultConfig)
		if err == nil {

			err = a.GetAwsSessionToken(ctx, vaultConfig)
		}
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "refresh aws session error", "err", err)
			// retry again soon
			interval = time.Hour
			// reset the old values
			os.Setenv("AWS_ACCESS_KEY_ID", oldAccessKey)
			os.Setenv("AWS_SECRET_ACCESS_KEY", oldSecretAccessKey)
			os.Setenv("AWS_SESSION_TOKEN", oldSessionToken)
		} else {
			interval = AwsSessionTokenRefreshInterval
		}
		span.Finish()
	}
}
