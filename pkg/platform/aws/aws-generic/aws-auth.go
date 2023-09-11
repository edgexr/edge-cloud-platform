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

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
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
	code, err := accessApi.GetSessionTokens(ctx, AWS_TOTP_SECRET_KEY)
	if err != nil {
		return err
	}
	return a.GetAwsSessionTokenWithCode(ctx, code)
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
