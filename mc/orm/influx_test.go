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
	"context"
	"net/http"
	"testing"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testPermShowClusterMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string, data *edgeproto.ClusterInstKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.ClusterInstKey{}
	if data != nil {
		in = data
	} else {
		in.ClusterKey.Name = "testcluster"
	}
	in.Organization = org
	dat := &ormapi.RegionClusterInstMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.ClusterInst = *in
	return mcClient.ShowClusterMetrics(uri, token, dat)
}

func testPermShowAppInstMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string, data *edgeproto.AppInstKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.AppInstKey{}
	if data != nil {
		in = data
	} else {
		in.ClusterInstKey.ClusterKey.Name = "testcluster"
	}
	in.AppKey.Organization = org
	dat := &ormapi.RegionAppInstMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.AppInst = *in
	return mcClient.ShowAppMetrics(uri, token, dat)
}

func testPermShowCloudletMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string, data *edgeproto.CloudletKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.CloudletKey{}
	if data != nil {
		in = data
	} else {
		in.Name = "testcloudlet"
	}
	in.Organization = org
	dat := &ormapi.RegionCloudletMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.Cloudlet = *in
	return mcClient.ShowCloudletMetrics(uri, token, dat)
}

func testPermShowClientMetrics(mcClient *mctestclient.Client, uri, token, region, org, selector string, data *edgeproto.AppInstKey) (*ormapi.AllMetrics, int, error) {
	in := &edgeproto.AppInstKey{}
	if data != nil {
		in = data
	}
	in.AppKey.Organization = org
	in.ClusterInstKey.ClusterKey.Name = "testcluster"
	dat := &ormapi.RegionClientApiUsageMetrics{}
	dat.Region = region
	dat.Selector = selector
	dat.AppInst = *in
	return mcClient.ShowClientApiUsageMetrics(uri, token, dat)
}

func testPermShowCloudletUsage(mcClient *mctestclient.Client, uri, token, region, org, selector string, data []edgeproto.CloudletKey) (*ormapi.AllMetrics, int, error) {
	dat := &ormapi.RegionCloudletMetrics{}
	if data != nil {
		dat.Cloudlets = data
	} else {
		in := &edgeproto.CloudletKey{}
		in.Name = "testcloudlet"
		in.Organization = org
		dat.Cloudlet = *in
	}
	dat.Region = region
	dat.Selector = selector
	return mcClient.ShowCloudletUsage(uri, token, dat)
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
	_, status, err := testPermShowAppInstMetrics(mcClient, uri, token, region, org, "cpu", nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// ClusterInst Metrics tests
	_, status, err = testPermShowClusterMetrics(mcClient, uri, token, region, org, "cpu", nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Cloudlet Metrics tests
	_, status, err = testPermShowCloudletMetrics(mcClient, uri, token, region, org, "utilization", nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Client Metrics tests
	_, status, err = testPermShowClientMetrics(mcClient, uri, token, region, org, "api", nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermTestMetrics(t *testing.T, mcClient *mctestclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// AppInst Metrics tests
	list, status, err := testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "cpu", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "mem", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "disk", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "network", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "connections", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	// multiple selector check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "cpu,mem", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "*", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, "bad region", devOrg, "cpu", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	// bad selector check
	list, status, err = testPermShowAppInstMetrics(mcClient, uri, devToken, region, devOrg, "bad selector", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid appinst selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// ClusterInst Metrics tests
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "cpu", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "mem", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "disk", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "network", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "tcp", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "udp", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, "bad region", devOrg, "cpu", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	// bad selector check
	list, status, err = testPermShowClusterMetrics(mcClient, uri, devToken, region, devOrg, "bad selector", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cluster selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// Cloudlet Metrics tests
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "utilization", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "network", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad region check
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, "bad region", operOrg, "utilization", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	// bad selector check
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "bad selector", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cloudlet selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// Client Metrics test
	list, status, err = testPermShowClientMetrics(mcClient, uri, devToken, region, devOrg, "api", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, list)

	// bad selector check
	list, status, err = testPermShowClientMetrics(mcClient, uri, devToken, region, devOrg, "bad selector", nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid dme selector: bad selector")
	require.Equal(t, http.StatusBadRequest, status)

	// invalid input check
	appInst := edgeproto.AppInstKey{
		AppKey: edgeproto.AppKey{
			Name: "drop measurements \\",
		},
	}
	list, status, err = testPermShowClientMetrics(mcClient, uri, devToken, region, devOrg, "cpu", &appInst)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid app")
	require.Equal(t, http.StatusBadRequest, status)
	cloudlet := edgeproto.CloudletKey{
		Name: "select * from api",
	}
	list, status, err = testPermShowCloudletMetrics(mcClient, uri, operToken, region, operOrg, "utilization", &cloudlet)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cloudlet")
	require.Equal(t, http.StatusBadRequest, status)
	cluster := edgeproto.ClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "\\'\\;drop measurement \"cloudlet-ipusage\"",
		},
	}
	list, status, err = testPermShowClusterMetrics(mcClient, uri, operToken, region, operOrg, "utilization", &cluster)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid cluster")
	require.Equal(t, http.StatusBadRequest, status)
}

func testInvalidOrgForCloudletUsage(t *testing.T, mcClient *mctestclient.Client, uri, adminToken, region, operOrg string) {
	// bad cloudlet name check
	invalidCloudlet := []edgeproto.CloudletKey{{Organization: "InvalidCloudletOrg"}}
	_, status, err := testPermShowCloudletUsage(mcClient, uri, adminToken, region, operOrg, "resourceusage", invalidCloudlet)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Cloudlet does not exist")
	require.Equal(t, http.StatusBadRequest, status)
}

func testMultipleOrgsForCloudletUsage(t *testing.T, mcClient *mctestclient.Client, uri, adminToken, region, operOrg1, operOrg2 string) {
	// bad cloudlet name check
	cloudlets := []edgeproto.CloudletKey{
		{Organization: operOrg1},
		{Organization: operOrg1}}
	_, status, err := testPermShowCloudletUsage(mcClient, uri, adminToken, region, "", "resourceusage", cloudlets)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
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

func TestValidateMethod(t *testing.T) {
	obj := ormapi.RegionClientApiUsageMetrics{
		Region: "test",
		AppInst: edgeproto.AppInstKey{
			ClusterInstKey: edgeproto.VirtualClusterInstKey{
				CloudletKey: edgeproto.CloudletKey{
					Name:         "testCloudlet",
					Organization: "testOperator",
				},
			},
		},
	}
	obj.Method = "RegisterClient"
	err := validateMethodString(&obj)
	require.NotNil(t, err, "RegisterClient cannot have cloudlet name, or org defined")

	obj.Method = "VerifyLocation"
	err = validateMethodString(&obj)
	require.NotNil(t, err, "VerifyLocation cannot have cloudlet name, or org defined")

	obj.Method = "FindCloudlet"
	err = validateMethodString(&obj)
	require.Nil(t, err, "FindCloudlet should work with cloudlet name/org")

	obj.Method = "PlatformFindCloudlet"
	err = validateMethodString(&obj)
	require.Nil(t, err, "PlatformFindCloudlet should work with cloudlet name/org")

	obj.Method = ""
	err = validateMethodString(&obj)
	require.Nil(t, err, "with no method specified cloudlet/cloudlet-org is allowed")

	obj.Method = "RegisterClient"
	// zero out appInst details
	obj.AppInst = edgeproto.AppInstKey{}
	err = validateMethodString(&obj)
	require.Nil(t, err, "RegisterClient should work without cloudlet name/org")

	obj.Method = "VerifyLocation"
	// zero out appInst details
	obj.AppInst = edgeproto.AppInstKey{}
	err = validateMethodString(&obj)
	require.Nil(t, err, "VerifyLocation should work without cloudlet name/org")

	obj.Method = "InvalidMethod"
	err = validateMethodString(&obj)
	require.NotNil(t, err, "Invalid method name should fail")
	require.Contains(t, err.Error(), "Method is invalid")
}
