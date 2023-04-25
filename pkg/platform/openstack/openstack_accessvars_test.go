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

package openstack

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/stretchr/testify/require"
)

func TestAccessVars(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	ckey := edgeproto.CloudletKey{
		Organization: "MobiledgeX",
		Name:         "unit-test",
	}
	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	accessVarsTestGood := make(map[string]string)
	accessVarsTestGood["OPENRC_DATA"] = "OS_AUTH_URL=https://openstacktest.mobiledgex.net:5000/v3\nOS_PROJECT_ID=12345\nOS_PROJECT_NAME=\"mex\"\nOS_USER_DOMAIN_NAME=\"Default\"\nOS_PROJECT_DOMAIN_ID=\"default\"\nOS_USERNAME=\"mexadmin\"\nOS_PASSWORD=password123\nOS_REGION_NAME=\"RegionOne\"\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3"
	accessVarsTestGood["CACERT_DATA"] = "XXXXXXXX"

	accessVarsTestNoCert := make(map[string]string)
	accessVarsTestNoCert["OPENRC_DATA"] = "OS_AUTH_URL=https://openstacktest.mobiledgex.net:5000/v3\nOS_PROJECT_ID=12345\nOS_PROJECT_NAME=\"mex\"\nOS_USER_DOMAIN_NAME=\"Default\"\nOS_PROJECT_DOMAIN_ID=\"default\"\nOS_USERNAME=\"mexadmin\"\nOS_PASSWORD=password123\nOS_REGION_NAME=\"RegionOne\"\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3"

	accessVarsTestBadOSVar := make(map[string]string)
	accessVarsTestBadOSVar["OPENRC_DATA"] = "OS_AUTH_URL=https://openstacktest.mobiledgex.net:5000/v3\nXX_PROJECT_ID=12345\nOS_PROJECT_NAME=\"mex\"\nOS_USER_DOMAIN_NAME=\"Default\"\nOS_PROJECT_DOMAIN_ID=\"default\"\nOS_USERNAME=\"mexadmin\"\nOS_PASSWORD=password123\nOS_REGION_NAME=\"RegionOne\"\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3"
	accessVarsTestBadOSVar["CACERT_DATA"] = "XXXXXXXX"

	accessVarsTestBlankLines := make(map[string]string)
	accessVarsTestBlankLines["OPENRC_DATA"] = "\n\nOS_AUTH_URL=https://openstacktest.mobiledgex.net:5000/v3\n\n\n\nOS_PROJECT_ID=12345\nOS_PROJECT_NAME=\"mex\"\n\n\nOS_USER_DOMAIN_NAME=\"Default\"\n\nOS_PROJECT_DOMAIN_ID=\"default\"\nOS_USERNAME=\"mexadmin\"\nOS_PASSWORD=password123\nOS_REGION_NAME=\"RegionOne\"\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3"
	accessVarsTestBlankLines["CACERT_DATA"] = "XXXXXXXX"

	accessVarsTestBlankVars := make(map[string]string)
	accessVarsTestBlankVars["OPENRC_DATA"] = "OS_AUTH_URL=https://openstacktest.mobiledgex.net:5000/v3\nOS_PROJECT_ID=12345\nOS_PROJECT_NAME=\"\"\nOS_USER_DOMAIN_NAME=\nOS_PROJECT_DOMAIN_ID=\"default\"\n=\"mexadmin\"\nOS_PASSWORD=password123\nOS_REGION_NAME=\"RegionOne\"\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3"
	accessVarsTestBlankVars["CACERT_DATA"] = "XXXXXXXX"

	accessVarsTestNoAuthURL := make(map[string]string)
	accessVarsTestNoAuthURL["OPENRC_DATA"] = "OS_PROJECT_ID=12345\nOS_PROJECT_NAME=\"mex\"\nOS_USER_DOMAIN_NAME=\"Default\"\nOS_PROJECT_DOMAIN_ID=\"default\"\nOS_USERNAME=\"mexadmin\"\nOS_PASSWORD=password123\nOS_REGION_NAME=\"RegionOne\"\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3"
	accessVarsTestNoAuthURL["CACERT_DATA"] = "XXXXXXXX"

	accessVarsTestCertOnly := make(map[string]string)
	accessVarsTestCertOnly["CACERT_DATA"] = "YYYYYYYY"

	var envvars = make(map[string]string)
	envvars["VAULT_TOKEN"] = "dummy"
	pc := edgeproto.PlatformConfig{
		EnvVar: envvars,
	}
	op := OpenstackPlatform{}
	o := vmlayer.VMPlatform{
		Type:       "openstack",
		VMProvider: &op,
	}
	var cloudlet = edgeproto.Cloudlet{
		Key: ckey,
	}

	// save tests
	err := o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestGood, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestGood result", "err", err)
	require.Nil(t, err)

	err = o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestNoCert, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestNoCert result", "err", err)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing CACERT_DATA")

	err = o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestBadOSVar, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestBadOSVar result", "err", err)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "must start with 'OS_' prefix")

	err = o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestBlankLines, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestBlankLines result", "err", err)
	require.Nil(t, err)

	err = o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestBlankVars, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestBlankVars result", "err", err)
	require.Nil(t, err)

	err = o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestNoAuthURL, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestNoAuthURL result", "err", err)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing OS_AUTH_URL")

	err = o.SaveCloudletAccessVars(ctx, &cloudlet, accessVarsTestCertOnly, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "accessVarsTestCertOnly result", "err", err)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing OPENRC_DATA")

	// update tests
	err = o.UpdateCloudletAccessVars(ctx, &cloudlet, accessVarsTestCertOnly, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "update with accessVarsTestCertOnly result", "err", err)
	require.Nil(t, err)

	err = o.UpdateCloudletAccessVars(ctx, &cloudlet, accessVarsTestNoCert, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "Update accessVarsTestNoCert result", "err", err)
	require.Nil(t, err)

	err = o.UpdateCloudletAccessVars(ctx, &cloudlet, accessVarsTestBadOSVar, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "Update accessVarsTestBadOSVar result", "err", err)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "must start with 'OS_' prefix")

	err = o.UpdateCloudletAccessVars(ctx, &cloudlet, accessVarsTestBlankLines, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "Update accessVarsTestBlankLines result", "err", err)
	require.Nil(t, err)

	err = o.UpdateCloudletAccessVars(ctx, &cloudlet, accessVarsTestBlankVars, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "Update accessVarsTestBlankVars result", "err", err)
	require.Nil(t, err)

	err = o.UpdateCloudletAccessVars(ctx, &cloudlet, accessVarsTestNoAuthURL, &pc, vaultConfig, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "Update accessVarsTestNoAuthURL result", "err", err)
	require.Nil(t, err)

	// accessVarsFromOpenrcData tests
	vars, err := accessVarsFromOpenrcData(accessVarsTestGood["OPENRC_DATA"])
	require.Nil(t, err)
	require.Equal(t, 10, len(vars))
	for k, v := range vars {
		switch k {
		case "OS_AUTH_URL":
			require.Equal(t, "https://openstacktest.mobiledgex.net:5000/v3", v)
		case "OS_PROJECT_ID":
			require.Equal(t, "12345", v)
		case "OS_PROJECT_NAME":
			require.Equal(t, "mex", v)
		case "OS_USER_DOMAIN_NAME":
			require.Equal(t, "Default", v)
		case "OS_PROJECT_DOMAIN_ID":
			require.Equal(t, "default", v)
		case "OS_USERNAME":
			require.Equal(t, "mexadmin", v)
		case "OS_PASSWORD":
			require.Equal(t, "password123", v)
		case "OS_REGION_NAME":
			require.Equal(t, "RegionOne", v)
		case "OS_INTERFACE":
			require.Equal(t, "public", v)
		case "OS_IDENTITY_API_VERSION":
			require.Equal(t, "3", v)
		default:
			require.Fail(t, "unexpected key", k, v)
		}
	}
}
