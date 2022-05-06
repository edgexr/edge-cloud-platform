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

package orm

import (
	"net/http"
	"testing"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterEvents(mcClient *mctestclient.Client, uri, token, region, org string, data *edgeproto.ClusterInstKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.ClusterInstKey{}
	if data != nil {
		in = data
	} else {
		in.ClusterKey.Name = "testcluster"
	}
	in.Organization = org
	dat := &ormapi.RegionClusterInstEvents{}
	dat.Region = region
	dat.ClusterInst = *in
	return mcClient.ShowClusterEvents(uri, token, dat)
}

func testPermShowAppInstEvents(mcClient *mctestclient.Client, uri, token, region, org string, data *edgeproto.AppInstKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.AppInstKey{}
	if data != nil {
		in = data
	} else {
		in.ClusterInstKey.ClusterKey.Name = "testcluster"
	}
	in.AppKey.Organization = org
	dat := &ormapi.RegionAppInstEvents{}
	dat.Region = region
	dat.AppInst = *in
	return mcClient.ShowAppEvents(uri, token, dat)
}

func testPermShowCloudletEvents(mcClient *mctestclient.Client, uri, token, region, org string, data *edgeproto.CloudletKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.CloudletKey{}
	if data != nil {
		in = data
	} else {
		in.Name = "testcloudlet"
	}
	in.Organization = org
	dat := &ormapi.RegionCloudletEvents{}
	dat.Region = region
	dat.Cloudlet = *in
	return mcClient.ShowCloudletEvents(uri, token, dat)
}

func badPermTestEvents(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// AppInst Metrics tests
	_, status, err := testPermShowAppInstEvents(mcClient, uri, token, region, org, nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// ClusterInst Metrics tests
	_, status, err = testPermShowClusterEvents(mcClient, uri, token, region, org, nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Cloudlet Metrics tests
	_, status, err = testPermShowCloudletEvents(mcClient, uri, token, region, org, nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermTestEvents(t *testing.T, mcClient *mctestclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// AppInst Metrics tests
	list, status, err := testPermShowAppInstEvents(mcClient, uri, devToken, region, devOrg, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowAppInstEvents(mcClient, uri, devToken, "bad region", devOrg, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	// ClusterInst Metrics tests
	list, status, err = testPermShowClusterEvents(mcClient, uri, devToken, region, devOrg, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowClusterEvents(mcClient, uri, devToken, "bad region", devOrg, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	// Cloudlet Metrics tests
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, region, operOrg, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, "bad region", operOrg, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	// invalid input check
	appInst := edgeproto.AppInstKey{
		AppKey: edgeproto.AppKey{
			Name: "drop measurements \\",
		},
	}
	list, status, err = testPermShowAppInstEvents(mcClient, uri, devToken, region, devOrg, &appInst)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid app")
	require.Equal(t, http.StatusBadRequest, status)
	cloudlet := edgeproto.CloudletKey{
		Name: "select * from api",
	}
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, region, operOrg, &cloudlet)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cloudlet")
	require.Equal(t, http.StatusBadRequest, status)
	cluster := edgeproto.ClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "\\'\\;drop measurement \"cloudlet-ipusage\"",
		},
	}
	list, status, err = testPermShowClusterEvents(mcClient, uri, operToken, region, operOrg, &cluster)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cluster")
	require.Equal(t, http.StatusBadRequest, status)

}
