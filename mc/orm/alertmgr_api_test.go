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
	fmt "fmt"
	"net/http"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func InitAlertmgrMock() (string, error) {
	testAlertMgrAddr := "http://dummyalertmgr.mobiledgex.net:9093"
	testAlertMgrConfig := "testAlertMgrConfig.yml"
	// start with clean configFile
	err := os.Remove(testAlertMgrConfig)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if fakeAlertmanager := alertmgr.NewAlertmanagerMock(testAlertMgrAddr, testAlertMgrConfig); fakeAlertmanager == nil {
		return "", fmt.Errorf("Failed to start alertmanager")
	}

	// Start up a sidecar server on an available port
	sidecarServer, err := alertmgr.NewSidecarServer(testAlertMgrAddr, testAlertMgrConfig, ":0", &alertmgr.TestInitInfo, "", "", "", false)
	if err != nil {
		return "", err
	}
	if err = sidecarServer.Run(); err != nil {
		return "", err
	}
	return sidecarServer.GetApiAddr(), nil
}

func testShowAlertReceiver(mcClient *mctestclient.Client, uri, token, region, org, name, username string) ([]ormapi.AlertReceiver, int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	dat := &ormapi.AlertReceiver{}
	dat.Name = name
	dat.AppInst = *in
	dat.User = username

	recs, status, err := mcClient.ShowAlertReceiver(uri, token, dat)
	return recs, status, err
}

func testCreateAlertReceiver(mcClient *mctestclient.Client, uri, token, region, org, name, rType, severity, username, email string, appInstKey *edgeproto.AppInstKey, cloudlet *edgeproto.CloudletKey) (int, error) {
	if appInstKey == nil && cloudlet == nil {
		appInstKey = &edgeproto.AppInstKey{}
		appInstKey.AppKey.Organization = org
	}
	dat := &ormapi.AlertReceiver{}
	dat.Severity = severity
	dat.Type = rType
	dat.Name = name
	dat.AppInst = *appInstKey
	if cloudlet != nil {
		dat.Cloudlet = *cloudlet
	}
	dat.User = username
	dat.Email = email

	status, err := mcClient.CreateAlertReceiver(uri, token, dat)
	return status, err
}

func testDeleteAlertReceiver(mcClient *mctestclient.Client, uri, token, region, org, name, rType, severity, username string) (int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	dat := &ormapi.AlertReceiver{}
	dat.Severity = severity
	dat.Type = rType
	dat.Name = name
	dat.AppInst = *in
	dat.User = username

	status, err := mcClient.DeleteAlertReceiver(uri, token, dat)
	return status, err

}

func testDeleteAlertReceiverWithClusterOrg(mcClient *mctestclient.Client, uri, token, region, org, name, rType, severity, username string) (int, error) {
	in := &edgeproto.AppInstKey{}
	in.ClusterInstKey.Organization = org
	dat := &ormapi.AlertReceiver{}
	dat.Severity = severity
	dat.Type = rType
	dat.Name = name
	dat.AppInst = *in
	dat.User = username

	status, err := mcClient.DeleteAlertReceiver(uri, token, dat)
	return status, err

}

func badPermTestAlertReceivers(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	status, err := testCreateAlertReceiver(mcClient, uri, token, region, org, "testAlert", "email", "error", "", "", nil, nil)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	status, err = testDeleteAlertReceiver(mcClient, uri, token, region, org, "testAlert", "email", "error", "")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	_, status, err = testShowAlertReceiver(mcClient, uri, token, region, org, "testAlert", "")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// test with no org - should return forbidden in either case
	_, status, err = testShowAlertReceiver(mcClient, uri, token, region, org, "testAlert", "")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func userPermTestAlertReceivers(t *testing.T, mcClient *mctestclient.Client, uri, devMgr, devMgrToken, dev, devToken, region, devOrg, operOrg string) {
	// mgrDeveloper creates a receiver
	status, err := testCreateAlertReceiver(mcClient, uri, devMgrToken, region, devOrg, "mgrReceiver", "email", "error", "", "", nil, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// Developer doesn't see the receiver
	list, status, err := testShowAlertReceiver(mcClient, uri, devToken, region, devOrg, "", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
	// Developer contributor creates a receiver
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "devReceiver", "email", "error", "", "", nil, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// Developer can only see it's own alert receiver
	list, status, err = testShowAlertReceiver(mcClient, uri, devToken, region, devOrg, "", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(list))
	require.Equal(t, "devReceiver", list[0].Name)
	// Manager only sees it's receivers by default
	list, status, err = testShowAlertReceiver(mcClient, uri, devMgrToken, region, devOrg, "", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(list))
	require.Equal(t, "mgrReceiver", list[0].Name)
	// Manager sees other developer's receivers if username is specified
	list, status, err = testShowAlertReceiver(mcClient, uri, devMgrToken, region, devOrg, "", dev)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(list))
	require.Equal(t, "devReceiver", list[0].Name)
	// Developer cannot see the receivers of others
	list, status, err = testShowAlertReceiver(mcClient, uri, devToken, region, devOrg, "", devMgr)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Developer cannot delete other user's receiver
	status, err = testDeleteAlertReceiver(mcClient, uri, devToken, region, devOrg, "mgrReceiver", "email", "error", devMgr)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// user cannot delete receiver from another org
	status, err = testDeleteAlertReceiverWithClusterOrg(mcClient, uri, devMgrToken, region, devOrg, "mgrReceiver", "email", "error", "otheruser")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// Manager can delete other user's receiver
	status, err = testDeleteAlertReceiver(mcClient, uri, devMgrToken, region, devOrg, "devReceiver", "email", "error", dev)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// Receiver was deleted
	list, status, err = testShowAlertReceiver(mcClient, uri, devToken, region, "", "", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
	// Delete it's own receiver
	status, err = testDeleteAlertReceiver(mcClient, uri, devMgrToken, region, "", "mgrReceiver", "email", "error", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	list, status, err = testShowAlertReceiver(mcClient, uri, devMgrToken, region, devOrg, "", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
}

func goodPermTestAlertReceivers(t *testing.T, mcClient *mctestclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// Permissions test
	status, err := testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "", "", nil, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// test with cluster org only
	appInst := edgeproto.AppInstKey{
		ClusterInstKey: edgeproto.VirtualClusterInstKey{
			Organization: devOrg,
		},
	}
	status, err = testDeleteAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "", "", &appInst, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	list, status, err := testShowAlertReceiver(mcClient, uri, devToken, region, "", "testAlert", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(list))
	status, err = testDeleteAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// missing name check
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "", "email", "error", "", "", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver name has to be specified")
	// invalid receiver name
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "%alertreceiver", "email", "error", "", "", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver name is invalid")
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "al\\!ertreceiver", "email", "error", "", "", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver name is invalid")
	// invalid receiver type check
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "invalid", "error", "", "", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver type invalid")
	// invalid severity check
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "slack", "invalid", "", "", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Alert severity has to be one of")
	// specifying a user in the call - disallowed
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "slack", "error", "user1", "", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "User is not specifiable")
	// invalid receiver email format
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "", "xx.com", nil, nil)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver email is invalid")
	// test combination of both appInst and cloudlet
	appInst = edgeproto.AppInstKey{
		AppKey: edgeproto.AppKey{
			Organization: devOrg,
		},
	}
	cloudlet := edgeproto.CloudletKey{
		Organization: operOrg,
	}
	status, err = testCreateAlertReceiver(mcClient, uri, operToken, region, devOrg, "testAlert", "email", "error", "", "", &appInst, &cloudlet)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "AppInst details cannot be specified if this receiver is for cloudlet alerts")
	// Check where app org is used
	cloudlet = edgeproto.CloudletKey{
		Name: "Operator",
	}
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "", "", &appInst, &cloudlet)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Cloudlet details cannot be specified if this receiver is for appInst or cluster alerts")

	// Clean up last receiver
	list, status, err = testShowAlertReceiver(mcClient, uri, devToken, region, "", "testAlert", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
}
