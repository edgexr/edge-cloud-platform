package orm

import (
	"net/http"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterEvents(mcClient *ormclient.Client, uri, token, region, org string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.ClusterInstKey{}
	in.Developer = org
	in.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionClusterInstMetrics{}
	dat.Region = region
	dat.ClusterInst = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/events/cluster", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func testPermShowAppInstEvents(mcClient *ormclient.Client, uri, token, region, org string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.AppInstKey{}
	in.AppKey.DeveloperKey.Name = org
	in.ClusterInstKey.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionAppInstMetrics{}
	dat.Region = region
	dat.AppInst = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/events/app", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func testPermShowCloudletEvents(mcClient *ormclient.Client, uri, token, region, org string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.CloudletKey{}
	in.Name = "testcloudlet"
	in.OperatorKey.Name = org
	dat := &ormapi.RegionCloudletMetrics{}
	dat.Region = region
	dat.Cloudlet = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/events/cloudlet", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func badPermTestEvents(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
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

func goodPermTestEvents(t *testing.T, mcClient *ormclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// AppInst Metrics tests
	list, status, err := testPermShowAppInstEvents(mcClient, uri, devToken, region, devOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))

	// bad region check
	list, status, err = testPermShowAppInstEvents(mcClient, uri, devToken, "bad region", devOrg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))

	// ClusterInst Metrics tests
	list, status, err = testPermShowClusterEvents(mcClient, uri, devToken, region, devOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))

	// bad region check
	list, status, err = testPermShowClusterEvents(mcClient, uri, devToken, "bad region", devOrg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))

	// Cloudlet Metrics tests
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, region, operOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))

	// bad region check
	list, status, err = testPermShowCloudletEvents(mcClient, uri, operToken, "bad region", operOrg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
}
