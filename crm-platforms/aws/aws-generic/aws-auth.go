// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awsgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

const SessionTokenDurationSecs = 60 * 60 * 24 // 24 hours
const AwsSessionTokenRefreshInterval = 12 * time.Hour
const TotpTokenName = "code"

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
func (a *AwsGenericPlatform) GetAwsSessionToken(ctx context.Context, accessApi platform.AccessApi) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAwsSessionToken")

	arn := a.GetAwsUserArn()
	if arn == "" {
		return fmt.Errorf("AWS_USER_ARN must be set to get session token")
	}
	user, err := a.GetUserAccountIdFromArn(ctx, arn)
	if err != nil {
		return err
	}
	// This calls to Controller which eventually calls GetAwsTotpToken() via GetAccessData
	tokens, err := accessApi.GetSessionTokens(ctx, []byte(user))
	if err != nil {
		return err
	}
	code, found := tokens[TotpTokenName]
	if !found {
		return fmt.Errorf("token key \"%s\" not found in aws session tokens", TotpTokenName)
	}
	return a.GetAwsSessionTokenWithCode(ctx, code)
}

// GetAwsTotpToken gets a totp token from the vault.
// Called only from the Controller context.
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
func (a *AwsGenericPlatform) RefreshAwsSessionToken(pfconfig *pf.PlatformConfig) {
	interval := AwsSessionTokenRefreshInterval
	for {
		select {
		case <-time.After(interval):
		}
		span := log.StartSpan(log.DebugLevelInfra, "refresh aws session token")
		ctx := log.ContextWithSpan(context.Background(), span)
		err := a.GetAwsSessionToken(ctx, pfconfig.AccessApi)
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

func (a *AwsGenericPlatform) GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	vaultPath := AwsDefaultVaultPath
	if key.Organization != "aws" {
		// this is not a public cloud aws cloudlet, use the operator specific path
		vaultPath = fmt.Sprintf("/secret/data/%s/cloudlet/aws/%s/%s/aws.json", region, key.Organization, physicalName)
	}
	return vaultPath
}

func (a *AwsGenericPlatform) GetAwsAccountAccessVars(ctx context.Context, accessApi platform.AccessApi) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAwsAccountAccessVars")

	vars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	a.AccountAccessVars = vars
	a.AccountAccessVars["AWS_REGION"] = a.GetAwsRegion()
	return nil
}
