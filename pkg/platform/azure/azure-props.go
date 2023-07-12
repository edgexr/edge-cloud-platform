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

package azure

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

const (
	AZURE_USER     = "AZURE_USER"
	AZURE_PASSWORD = "AZURE_PASSWORD"
)

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	AZURE_USER: {
		Name:      "Azure user name",
		Mandatory: true,
	},
	AZURE_PASSWORD: {
		Name:      "Azure user password",
		Mandatory: true,
	},
}

var azureProps = map[string]*edgeproto.PropertyInfo{
	"MEX_AZURE_LOCATION": {
		Name:        "Azure Location",
		Description: "Azure Location",
		Mandatory:   true,
	},
}

func (a *AzurePlatform) GetAzureLocation() string {
	val, _ := a.properties.GetValue("MEX_AZURE_LOCATION")
	return val
}

func (a *AzurePlatform) GetAzureUser() string {
	val, _ := a.accessVars[AZURE_USER]
	return val
}

func (a *AzurePlatform) GetAzurePass() string {
	val, _ := a.accessVars[AZURE_PASSWORD]
	return val
}

func (a *AzurePlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetProviderSpecificProps")
	return azureProps, nil
}

func (a *AzurePlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AzurePlatform GetAccessData", "dataType", dataType)
	return nil, fmt.Errorf("Azure unhandled GetAccessData type %s", dataType)
}

func (a *AzurePlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	accessVars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	a.accessVars = accessVars
	return nil
}
