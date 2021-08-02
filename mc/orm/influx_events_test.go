package orm

import (
	"net/http"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
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
	require.Contains(t, err.Error(), "Invalid app passed in")
	require.Equal(t, http.StatusBadRequest, status)
	cloudlet := edgeproto.CloudletKey{
		Name: "select * from api",
	}
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, region, operOrg, &cloudlet)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cloudlet passed in")
	require.Equal(t, http.StatusBadRequest, status)
	cluster := edgeproto.ClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "\\'\\;drop measurement \"cloudlet-ipusage\"",
		},
	}
	list, status, err = testPermShowClusterEvents(mcClient, uri, operToken, region, operOrg, &cluster)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cluster passed in")
	require.Equal(t, http.StatusBadRequest, status)

}
