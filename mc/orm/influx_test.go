package orm

import (
	"context"
	"net/http"
	"testing"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.ClusterInstKey{}
	in.Organization = org
	in.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionClusterInstMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.ClusterInst = *in
	return mcClient.ShowClusterMetrics(uri, token, dat)
}

func testPermShowAppInstMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	in.ClusterInstKey.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionAppInstMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.AppInst = *in
	return mcClient.ShowAppMetrics(uri, token, dat)
}

func testPermShowCloudletMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Name = "testcloudlet"
	in.Organization = org
	dat := &ormapi.RegionCloudletMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.Cloudlet = *in
	return mcClient.ShowCloudletMetrics(uri, token, dat)
}

func testPermShowClientMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	in.ClusterInstKey.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionClientApiUsageMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.AppInst = *in
	return mcClient.ShowClientApiUsageMetrics(uri, token, dat)
}

func testPassCheckPermissionsAndGetCloudletList(t *testing.T, ctx context.Context, username, region string, devOrgs []string,
	resource string, cloudletKeys []edgeproto.CloudletKey, expectedCloudlets []string) {

	list, err := checkPermissionsAndGetCloudletList(ctx, username, region, devOrgs, resource, cloudletKeys)
	require.Nil(t, err)
	require.ElementsMatch(t, expectedCloudlets, list)
}

func testFailCheckPermissionsAndGetCloudletList(t *testing.T, ctx context.Context, username, region string, devOrgs []string,
	resource string, cloudletKeys []edgeproto.CloudletKey, errorContains string) {

	list, err := checkPermissionsAndGetCloudletList(ctx, username, region, devOrgs, resource, cloudletKeys)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), errorContains)
	require.Empty(t, list)
}

func badPermTestMetrics(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
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
	// Client Metrics tests
	_, status, err = testPermShowClientMetrics(mcClient, uri, token, region, org, "api")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermTestMetrics(t *testing.T, mcClient *mctestclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// AppInst Metrics tests
	list, status, err := testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "cpu")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "mem")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "disk")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "network")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "connections")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	// multiple selector check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "cpu,mem")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "*")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, "bad region", devOrg, "cpu")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	// bad selector check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid appinst selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// ClusterInst Metrics tests
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "cpu")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "mem")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "disk")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "network")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "tcp")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "udp")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, "bad region", devOrg, "cpu")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	// bad selector check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cluster selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// Cloudlet Metrics tests
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "utilization")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "network")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, "bad region", operOrg, "utilization")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	// bad selector check
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cloudlet selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// Client Metrics test
	list, status, err = testPermShowClientMetrics(mcClient, uri, devToken, region, devOrg, "api")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad selector check
	list, status, err = testPermShowClientMetrics(mcClient, uri, devToken, region, devOrg, "bad selector")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid dme selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)
}

func TestIsMeasurementOutputEmpty(t *testing.T) {
	// check for nil
	empty, err := isMeasurementOutputEmpty(nil, EVENT_CLUSTERINST)
	require.NotNil(t, err, "Null response is an error")
	require.Contains(t, err.Error(), "Error processing nil response")
	require.False(t, empty)

	// check empty result
	resp := client.Response{}
	empty, err = isMeasurementOutputEmpty(&resp, EVENT_CLUSTERINST)
	require.Nil(t, err, "Empty response should not trigger an error")
	require.True(t, empty)

	// check invalid series data - multiple results in the response
	resp = client.Response{
		Results: []client.Result{
			client.Result{},
			client.Result{},
		},
	}

	// check invalid series data - multiple series in a response is not allowed
	resp = client.Response{
		Results: []client.Result{
			client.Result{
				Series: []models.Row{
					models.Row{},
					models.Row{},
				},
			},
		},
	}
	testInvalidMeasurementData(t, &resp, EVENT_CLUSTERINST)

	// check invalid series data - series value should not be empty
	resp = client.Response{
		Results: []client.Result{
			client.Result{
				Series: []models.Row{
					models.Row{
						Name:   EVENT_CLUSTERINST,
						Values: [][]interface{}{},
					},
				},
			},
		},
	}
	testInvalidMeasurementData(t, &resp, EVENT_CLUSTERINST)

	// check invalid series data - series value[0] should not be empty
	vals := [][]uint8{{}}
	valIf := [][]interface{}{}
	for ii, _ := range vals {
		ifArray := make([]interface{}, len(vals[ii]))
		for jj, v := range vals[ii] {
			ifArray[jj] = v
		}
		valIf = append(valIf, ifArray)
	}
	resp = client.Response{
		Results: []client.Result{
			client.Result{
				Series: []models.Row{
					models.Row{
						Name:   EVENT_CLUSTERINST,
						Values: valIf,
					},
				},
			},
		},
	}
	testInvalidMeasurementData(t, &resp, EVENT_CLUSTERINST)

	// check invalid series data - series name should match
	vals = [][]uint8{{0, 1, 2, 3}, {0, 1, 2, 3}}
	valIf = [][]interface{}{}
	for ii, _ := range vals {
		ifArray := make([]interface{}, len(vals[ii]))
		for jj, v := range vals[ii] {
			ifArray[jj] = v
		}
		valIf = append(valIf, ifArray)
	}
	resp = client.Response{
		Results: []client.Result{
			client.Result{
				Series: []models.Row{
					models.Row{
						Name:   "invalidName",
						Values: valIf,
					},
				},
			},
		},
	}
	testInvalidMeasurementData(t, &resp, EVENT_CLUSTERINST)

	// check valid series data
	vals = [][]uint8{{0, 1, 2, 3}, {0, 1, 2, 3}}
	valIf = [][]interface{}{}
	for ii, _ := range vals {
		ifArray := make([]interface{}, len(vals[ii]))
		for jj, v := range vals[ii] {
			ifArray[jj] = v
		}
		valIf = append(valIf, ifArray)
	}
	resp = client.Response{
		Results: []client.Result{
			client.Result{
				Series: []models.Row{
					models.Row{
						Name:   EVENT_CLUSTERINST,
						Values: valIf,
					},
				},
			},
		},
	}
	empty, err = isMeasurementOutputEmpty(&resp, EVENT_CLUSTERINST)
	require.Nil(t, err)
	require.False(t, empty)
}

func testInvalidMeasurementData(t *testing.T, resp *client.Response, measurement string) {
	empty, err := isMeasurementOutputEmpty(resp, measurement)
	require.NotNil(t, err, "Invalid series data")
	require.Contains(t, err.Error(), "Error parsing influx, unexpected format")
	require.False(t, empty)
}
