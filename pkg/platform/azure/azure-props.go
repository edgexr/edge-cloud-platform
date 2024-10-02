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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

const (
	AZURE_CLIENT_ID       = "AZURE_CLIENT_ID"
	AZURE_CLIENT_SECRET   = "AZURE_CLIENT_SECRET"
	AZURE_SUBSCRIPTION_ID = "AZURE_SUBSCRIPTION_ID"
	AZURE_TENANT_ID       = "AZURE_TENANT_ID"
	AZURE_RESOURCE_GROUP  = "AZURE_RESOURCE_GROUP"
	AZURE_LOCATION        = "AZURE_LOCATION"
)

// Azure authentication is done using a service principal

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	AZURE_CLIENT_ID: {
		Name:      "Azure application ID of an Azure service principal, requires roles \"Reader\" and \"Azure Kubernetes Service Contributor\", see https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles. Recommend scoping to a resource group.",
		Mandatory: true,
	},
	AZURE_CLIENT_SECRET: {
		Name:      "Password of the Azure service principal",
		Mandatory: true,
	},
	AZURE_SUBSCRIPTION_ID: {
		Name:      "Azure subscription ID",
		Mandatory: true,
	},
	AZURE_TENANT_ID: {
		Name:      "Azure tenant ID",
		Mandatory: true,
	},
	AZURE_RESOURCE_GROUP: {
		Name:      "Azure resource group in which to create resources, must already exist",
		Mandatory: true,
	},
}

var azureProps = map[string]*edgeproto.PropertyInfo{
	AZURE_LOCATION: {
		Name:        "Azure geo-location of Cloudlet, i.e. \"westus\"",
		Description: "Azure geo-location of Cloudlet, i.e. \"westus\"",
		Mandatory:   true,
	},
}

func (a *AzurePlatform) GetAzureLocation() string {
	val, _ := a.properties.GetValue(AZURE_LOCATION)
	return val
}

func (a *AzurePlatform) GetAzureUser() string {
	return a.accessVars[AZURE_CLIENT_ID]
}

func (a *AzurePlatform) GetAzurePass() string {
	return a.accessVars[AZURE_CLIENT_SECRET]
}

func (a *AzurePlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	accessVars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	a.accessVars = accessVars
	return nil
}
