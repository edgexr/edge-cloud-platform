package orm

import (
	"net/http"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterEvents(mcClient *mctestclient.Client, uri, token, region, org string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.ClusterInstKey{}
	in.Organization = org
	in.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionClusterInstEvents{}
	dat.Region = region
	dat.ClusterInst = *in
	return mcClient.ShowClusterEvents(uri, token, dat)
}

func testPermShowAppInstEvents(mcClient *mctestclient.Client, uri, token, region, org string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	in.ClusterInstKey.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionAppInstEvents{}
	dat.Region = region
	dat.AppInst = *in
	return mcClient.ShowAppEvents(uri, token, dat)
}

func testPermShowCloudletEvents(mcClient *mctestclient.Client, uri, token, region, org string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Name = "testcloudlet"
	in.Organization = org
	dat := &ormapi.RegionCloudletEvents{}
	dat.Region = region
	dat.Cloudlet = *in
	return mcClient.ShowCloudletEvents(uri, token, dat)
}

func badPermTestEvents(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// AppInst Metrics tests
	_, status, err := testPermShowAppInstEvents(mcClient, uri, token, region, org)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// ClusterInst Metrics tests
	_, status, err = testPermShowClusterEvents(mcClient, uri, token, region, org)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Cloudlet Metrics tests
	_, status, err = testPermShowCloudletEvents(mcClient, uri, token, region, org)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermTestEvents(t *testing.T, mcClient *mctestclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// AppInst Metrics tests
	list, status, err := testPermShowAppInstEvents(mcClient, uri, devToken, region, devOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowAppInstEvents(mcClient, uri, devToken, "bad region", devOrg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	// ClusterInst Metrics tests
	list, status, err = testPermShowClusterEvents(mcClient, uri, devToken, region, devOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowClusterEvents(mcClient, uri, devToken, "bad region", devOrg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	// Cloudlet Metrics tests
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, region, operOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, "bad region", operOrg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
}
