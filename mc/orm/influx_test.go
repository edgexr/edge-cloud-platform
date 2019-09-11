package orm

import (
	"net/http"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterMetrics(mcClient *ormclient.Client, uri, token, region, org, selector string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.ClusterInstKey{}
	in.Developer = org
	in.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionClusterInstMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.ClusterInst = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/metrics/cluster", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func testPermShowAppInstMetrics(mcClient *ormclient.Client, uri, token, region, org, selector string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.AppInstKey{}
	in.AppKey.DeveloperKey.Name = org
	in.ClusterInstKey.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionAppInstMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.AppInst = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/metrics/app", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func testPermShowCloudletMetrics(mcClient *ormclient.Client, uri, token, region, org, selector string) ([]interface{}, int, error) {
	var out interface{}
	var data []interface{}

	in := &edgeproto.CloudletKey{}
	in.Name = "testcloudlet"
	in.OperatorKey.Name = org
	dat := &ormapi.RegionCloudletMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.Cloudlet = *in
	status, err := mcClient.PostJsonStreamOut(uri+"/auth/metrics/cloudlet", token, dat, &out, func() {
		data = append(data, out)
	})
	return data, status, err
}

func badPermTestMetrics(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	// AppInst Metrics tests
	_, status, err := testPermShowAppInstMetrics(mcClient, uri, token, region, org, "cpu")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// ClusterInst Metrics tests
	_, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "cpu")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Cloudlet Metrics tests
	_, status, err = testPermShowCloudletMetrics(mcClient, uri, token, region, org, "utilization")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermTestMetrics(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	// AppInst Metrics tests
	list, status, err := testPermShowAppInstMetrics(mcClient, uri, token, region, org, "cpu")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, region, org, "mem")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, region, org, "disk")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, region, org, "network")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, region, org, "connections")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))

	// bad region check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, "bad region", org, "cpu")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
	// multiple selector check - TODO: EDGECLOUD-940 this should be passing
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, region, org, "cpu,mem")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid selector in a request")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
	// bad selector check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, token, region, org, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid selector in a request")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))

	// ClusterInst Metrics tests
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "cpu")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "mem")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "disk")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "network")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "tcp")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "udp")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))

	// bad region check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, "bad region", org, "cpu")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
	// bad selector check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid selector in a request")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))

	// Cloudlet Metrics tests
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, token, region, org, "utilization")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, token, region, org, "network")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, 0, len(list))

	// bad region check
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, token, "bad region", org, "utilization")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
	// bad selector check
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, token, region, org, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid selector in a request")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))

}
