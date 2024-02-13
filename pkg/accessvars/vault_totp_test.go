// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package accessvars

import (
	"context"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func testCloudletTotp(t *testing.T, ctx context.Context, vaultConfig *vault.Config, region string) {
	cloudlet := &testutil.CloudletData()[0]

	// to validate, create a totp generator
	generatedKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "UnitTest",
		AccountName: "unit-test",
		Period:      300,
		Digits:      6,
	})
	require.Nil(t, err)

	secretName := "platform_totp_key"
	secretKey := generatedKey.Secret()

	err = SaveCloudletTotpSecret(ctx, region, cloudlet, vaultConfig, secretName, secretKey)
	require.Nil(t, err)

	code, err := GetCloudletTotpCode(ctx, region, cloudlet, vaultConfig, secretName)
	require.Nil(t, err)
	// Compare to expected
	codeExp, err := totp.GenerateCode(secretKey, time.Now().UTC())
	require.Nil(t, err)
	require.Equal(t, codeExp, code)

	err = DeleteCloudletTotpSecret(ctx, region, cloudlet, vaultConfig, secretName)
	require.Nil(t, err)

	// Ensure it was deleted
	_, err = GetCloudletTotpCode(ctx, region, cloudlet, vaultConfig, secretName)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unknown key")
}
