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

package alertmgr

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"

	//	open_api_models "github.com/prometheus/alertmanager/api/v2/models"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly

	// alertmanager_config "github.com/prometheus/alertmanager/config"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	alertmanager_config "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/config"

	//	"github.com/prometheus/common/model"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly

	"github.com/stretchr/testify/require"
)

func TestAlertMgrServer(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	// mock http to redirect requests
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	// any requests that don't have a registered URL will be fetched normally
	httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)

	testAlertMgrAddr := "http://dummyalertmgr.mobiledgex.net:9093"
	testAlertMgrConfig := "testAlertMgrConfig.yml"
	// start with clean configFile
	err := os.Remove(testAlertMgrConfig)
	if err != nil && !os.IsNotExist(err) {
		require.Fail(t, "cannot remove alertmanager config file", err)
	}
	fakeAlertmanager := NewAlertmanagerMock(testAlertMgrAddr, testAlertMgrConfig)
	require.NotNil(t, fakeAlertmanager)
	// Empty file - should have nothing
	fakeAlertmanager.verifyAlertCnt(t, 0)
	fakeAlertmanager.verifyReceiversCnt(t, 0)

	// Start up a sidecar server on an available port
	sidecarServer, err := NewSidecarServer(testAlertMgrAddr, testAlertMgrConfig, ":0", &TestInitInfo, "", "", "", false)
	require.Nil(t, err)
	err = sidecarServer.Run()
	require.Nil(t, err)
	sidecarServerAddr := sidecarServer.GetApiAddr()

	// Create a connection to fake alertmanager
	var testAlertCache edgeproto.AlertCache
	edgeproto.InitAlertCache(&testAlertCache)
	alertRefreshInterval = 100 * time.Millisecond
	testAlertMgrServer, err := NewAlertMgrServer(sidecarServerAddr, nil, &testAlertCache, 2*time.Minute)
	require.Nil(t, err)
	require.NotNil(t, testAlertMgrServer)
	require.Equal(t, 1, fakeAlertmanager.ConfigReloads)
	// start another test alertMgrServer to test multiple inits
	testAlertMgrServer2, err := NewAlertMgrServer(sidecarServerAddr, nil, &testAlertCache, 2*time.Minute)
	require.Nil(t, err)
	require.NotNil(t, testAlertMgrServer2)
	// config is already set up, don't need to reload
	require.Equal(t, 1, fakeAlertmanager.ConfigReloads)
	// We should still not have any configuration
	fakeAlertmanager.verifyAlertCnt(t, 0)
	// Default is one receiver
	fakeAlertmanager.verifyReceiversCnt(t, 1)
	// Make sure that the values for the global config are correct
	config, err := alertmanager_config.LoadFile(testAlertMgrConfig)
	require.Nil(t, err)
	require.Equal(t, TestInitInfo.Email, config.Global.SMTPFrom)
	require.Equal(t, TestInitInfo.User, config.Global.SMTPAuthUsername)
	require.Equal(t, TestInitInfo.Smtp, config.Global.SMTPSmarthost.Host)
	require.Equal(t, TestInitInfo.Port, config.Global.SMTPSmarthost.Port)
	require.Equal(t, TestInitInfo.Token, string(config.Global.SMTPAuthPassword))
	require.Equal(t, (TestInitInfo.Tls == "true"), config.Global.SMTPRequireTLS)

	testAlertCache.SetUpdatedCb(testAlertMgrServer.UpdateAlert)

	// Check that an alert notification triggers an api call to alertmgr
	testAlertCache.Update(ctx, &testAlerts[0], 0)
	// Test alertmgr create alert api
	fakeAlertmanager.verifyAlertCnt(t, 1)
	fakeAlertmanager.verifyAlertPresent(t, &testAlerts[0])
	require.Equal(t, 1, fakeAlertmanager.AlertPosts)

	// Start server after testing the watcher
	testAlertMgrServer.Start()
	// Wait refresh interval and check that the same alert is refreshed
	time.Sleep(alertRefreshInterval * 2)
	require.GreaterOrEqual(t, 2, fakeAlertmanager.AlertPosts)
	fakeAlertmanager.verifyAlertCnt(t, 1)
	fakeAlertmanager.verifyAlertPresent(t, &testAlerts[0])
	// Delete alert and check that alert doesn't get refreshed
	testAlertCache.Delete(ctx, &testAlerts[0], 0)
	// Make sure the last message was sent, since alertmgrserver is running in a separate thread
	time.Sleep(alertRefreshInterval)
	cnt := fakeAlertmanager.AlertPosts
	time.Sleep(alertRefreshInterval * 2)
	require.Equal(t, cnt, fakeAlertmanager.AlertPosts)
	// TODO - how to test alert timeout
	//fakeAlertmanager.verifyAlertCnt(t, 0)
	//    4.1. Can we delete alert from alertmgr right away?
	//    TODO
	// Create the alert again
	fakeAlertmanager.resetCounters()
	testAlertCache.Update(ctx, &testAlerts[0], 0)
	fakeAlertmanager.verifyAlertCnt(t, 1)
	fakeAlertmanager.verifyAlertPresent(t, &testAlerts[0])
	require.GreaterOrEqual(t, fakeAlertmanager.AlertPosts, 1)
	// Create the same alert, but in a different region
	testAlertCache.Update(ctx, &testAlerts[1], 0)
	fakeAlertmanager.verifyAlertCnt(t, 2)
	fakeAlertmanager.verifyAlertPresent(t, &testAlerts[1])
	// Raise an internal alert - should not get propagated to alertmanager
	testAlertCache.Update(ctx, &testAlerts[2], 0)
	fakeAlertmanager.verifyAlertCnt(t, 2)
	// Test alertmgr show alert api
	alerts, err := testAlertMgrServer.ShowAlerts(ctx, nil)
	require.Nil(t, err)
	require.Equal(t, 1, fakeAlertmanager.AlertGets)
	require.Equal(t, 2, len(alerts))
	for _, alert := range alerts {
		val, found := alert.Labels["alertname"]
		require.True(t, found)
		require.Equal(t, cloudcommon.AlertAppInstDown, val)
		val, found = alert.Labels[edgeproto.AppKeyTagName]
		require.True(t, found)
		require.Equal(t, "testapp", val)
		val, found = alert.Labels[edgeproto.AppKeyTagOrganization]
		require.True(t, found)
		require.Equal(t, "testorg", val)
		val, found = alert.Labels[edgeproto.AppKeyTagVersion]
		require.True(t, found)
		require.Equal(t, "1.0", val)
		val, found = alert.Labels[edgeproto.CloudletKeyTagName]
		require.True(t, found)
		require.Equal(t, "testcloudlet", val)
		val, found = alert.Labels[cloudcommon.AlertHealthCheckStatus]
		require.True(t, found)
		require.Equal(t, dme.HealthCheck_CamelName[int32(dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE)], val)
		region, ok := alert.Labels["region"]
		require.True(t, ok)
		if ok {
			if region != testRegions[0] {
				require.Equal(t, testRegions[1], region)
			}
		}
	}

	// 7. Test alertmgr create receiver api
	// Invalid receiver test
	err = testAlertMgrServer.CreateReceiver(ctx, &testAlertReceivers[0])
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid receiver type")
	require.Contains(t, err.Error(), testAlertReceivers[0].Type)

	err = testAlertMgrServer.CreateReceiver(ctx, &testAlertReceivers[1])
	require.Nil(t, err)
	require.Equal(t, 1, fakeAlertmanager.ConfigReloads)
	fakeAlertmanager.verifyReceiversCnt(t, 2)
	// Validate receivers
	receiver := fakeAlertmanager.findReceiver(&testAlertReceivers[1])
	require.NotNil(t, receiver)
	require.Len(t, receiver.EmailConfigs, 1)
	require.Equal(t, testAlertReceivers[1].Email, receiver.EmailConfigs[0].To)
	// check route and labels
	route := fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[1])
	require.NotNil(t, route)
	routeLblVal, found := route.Match[edgeproto.AppKeyTagName]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[1].AppInst.AppKey.Name)
	routeLblVal, found = route.Match[edgeproto.AppKeyTagOrganization]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[1].AppInst.AppKey.Organization)

	// Verify ShowReceivers
	receivers, err := testAlertMgrServer.ShowReceivers(ctx, nil)
	require.Nil(t, err)
	// should be a single receiver
	require.Len(t, receivers, 1)
	// check the receiver and all fields
	require.Equal(t, testAlertReceivers[1], receivers[0])

	// Verify ShowReceivers with a filter
	filter := ormapi.AlertReceiver{
		Name: testAlertReceivers[1].Name,
	}
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, &filter)
	require.Nil(t, err)
	// should be a single receiver
	require.Len(t, receivers, 1)
	// check the receiver and all fields
	require.Equal(t, testAlertReceivers[1], receivers[0])
	// Non-existent receiver
	filter = ormapi.AlertReceiver{
		Name: testAlertReceivers[0].Name,
	}
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, &filter)
	require.Nil(t, err)
	// should be empty response
	require.Len(t, receivers, 0)
	// Non-existent receiver by appname
	filter = ormapi.AlertReceiver{
		AppInst: edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name: "invalidAppName",
			},
		},
	}
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, &filter)
	require.Nil(t, err)
	// should be empty response
	require.Len(t, receivers, 0)
	// filter by type and appInst name
	filter = ormapi.AlertReceiver{
		Type: AlertReceiverTypeEmail,
		AppInst: edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name: "testApp",
			},
		},
	}
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, &filter)
	require.Nil(t, err)
	// should be a single receiver
	require.Len(t, receivers, 1)
	// check the receiver and all fields
	require.Equal(t, testAlertReceivers[1], receivers[0])

	// Delete non-existent receiver
	err = testAlertMgrServer.DeleteReceiver(ctx, &testAlertReceivers[0])
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "No receiver")
	require.Contains(t, err.Error(), "bad response status 404 Not Found")
	require.Equal(t, 1, fakeAlertmanager.ConfigReloads)
	fakeAlertmanager.verifyReceiversCnt(t, 2)
	// Delete email receiver and verify it's deleted
	err = testAlertMgrServer.DeleteReceiver(ctx, &testAlertReceivers[1])
	require.Nil(t, err)
	require.Equal(t, 2, fakeAlertmanager.ConfigReloads)
	fakeAlertmanager.verifyReceiversCnt(t, 1)
	receiver = fakeAlertmanager.findReceiver(&testAlertReceivers[1])
	require.Nil(t, receiver)
	// Only receiver should be a default one
	require.Equal(t, "default", fakeAlertmanager.receivers[0].Name)
	route = fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[1])
	require.Nil(t, route)
	// check routes
	route = fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[1])
	require.Nil(t, route)
	// Verify ShowReceivers is empty
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, nil)
	require.Nil(t, err)
	require.Len(t, receivers, 0)

	// Test slack receivers
	// Invalid receiver - missing slack details
	err = testAlertMgrServer.CreateReceiver(ctx, &testAlertReceivers[2])
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Invalid Slack api URL")

	err = testAlertMgrServer.CreateReceiver(ctx, &testAlertReceivers[3])
	require.Nil(t, err)
	require.Equal(t, 3, fakeAlertmanager.ConfigReloads)
	fakeAlertmanager.verifyReceiversCnt(t, 2)
	// Validate receivers
	receiver = fakeAlertmanager.findReceiver(&testAlertReceivers[3])
	require.NotNil(t, receiver)
	require.Len(t, receiver.SlackConfigs, 1)
	require.Equal(t, testAlertReceivers[3].SlackWebhook, receiver.SlackConfigs[0].APIURL.String())

	// check route and labels
	route = fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[3])
	require.NotNil(t, route)
	routeLblVal, found = route.Match[edgeproto.AppKeyTagName]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[3].AppInst.AppKey.Name)
	routeLblVal, found = route.Match[edgeproto.AppKeyTagOrganization]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[3].AppInst.AppKey.Organization)

	// Verify ShowReceivers
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, nil)
	require.Nil(t, err)
	// should be a single receiver
	require.Len(t, receivers, 1)
	// check that webhook is hidden
	require.Equal(t, AlertMgrDisplayHidden, receivers[0].SlackWebhook)
	// set webhook so next comparison doesn't fail
	receivers[0].SlackWebhook = testAlertReceivers[3].SlackWebhook
	// check the receiver and all fields
	require.Equal(t, testAlertReceivers[3], receivers[0])

	// Delete slack receiver and verify it's deleted
	err = testAlertMgrServer.DeleteReceiver(ctx, &testAlertReceivers[3])
	require.Nil(t, err)
	require.Equal(t, 4, fakeAlertmanager.ConfigReloads)
	fakeAlertmanager.verifyReceiversCnt(t, 1)
	receiver = fakeAlertmanager.findReceiver(&testAlertReceivers[3])
	require.Nil(t, receiver)
	// Only receiver should be a default one
	require.Equal(t, "default", fakeAlertmanager.receivers[0].Name)
	route = fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[3])
	require.Nil(t, route)
	// check routes
	route = fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[3])
	require.Nil(t, route)
	// Verify ShowReceivers is empty
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, nil)
	require.Nil(t, err)
	require.Len(t, receivers, 0)

	// Test cluster alert receivers
	err = testAlertMgrServer.CreateReceiver(ctx, &testAlertReceivers[4])
	require.Nil(t, err)
	fakeAlertmanager.verifyReceiversCnt(t, 2)
	// Validate receivers
	receiver = fakeAlertmanager.findReceiver(&testAlertReceivers[4])
	require.NotNil(t, receiver)
	require.Len(t, receiver.EmailConfigs, 1)
	require.Equal(t, testAlertReceivers[4].Email, receiver.EmailConfigs[0].To)
	// check route and labels
	route = fakeAlertmanager.findRouteByReceiver(&testAlertReceivers[4])
	require.NotNil(t, route)
	routeLblVal, found = route.Match[edgeproto.ClusterInstKeyTagOrganization]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[4].AppInst.ClusterInstKey.Organization)
	routeLblVal, found = route.Match[edgeproto.ClusterKeyTagName]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[4].AppInst.ClusterInstKey.ClusterKey.Name)
	routeLblVal, found = route.Match[edgeproto.CloudletKeyTagName]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[4].AppInst.ClusterInstKey.CloudletKey.Name)
	routeLblVal, found = route.Match[edgeproto.CloudletKeyTagOrganization]
	require.True(t, found)
	require.Equal(t, routeLblVal, testAlertReceivers[4].AppInst.ClusterInstKey.CloudletKey.Organization)

	// Verify ShowReceivers
	receivers, err = testAlertMgrServer.ShowReceivers(ctx, nil)
	require.Nil(t, err)
	// should be a single receiver
	require.Len(t, receivers, 1)
	// check the receiver and all fields
	require.Equal(t, testAlertReceivers[4], receivers[0])

	// TODO - test silencers
	testAlertMgrServer.Stop()
}
