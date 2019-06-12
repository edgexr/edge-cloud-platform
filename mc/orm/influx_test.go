package orm

import (
	"net/http"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterMetrics(mcClient *ormclient.Client, uri, token, region, org string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.ClusterInstKey{}
	in.Developer = org
	dat := &ormapi.RegionClusterInstMetrics{}
	dat.Region = region
	dat.ClusterInst = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/metrics/cluster", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func testPermShowAppInstMetrics(mcClient *ormclient.Client, uri, token, region, org string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.AppInstKey{}
	in.AppKey.DeveloperKey.Name = org
	dat := &ormapi.RegionAppInstMetrics{}
	dat.Region = region
	dat.AppInst = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/metrics/app", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func badPermTestMetrics(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	_, status, err := testPermShowAppInstMetrics(mcClient, uri, token, region, org)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	_, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermTestMetrics(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	list, status, err := testPermShowAppInstMetrics(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	// bad region check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, "bad region", org)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))

	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	// bad region check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, "bad region", org)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
}
