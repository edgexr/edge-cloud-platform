package orm

import (
	fmt "fmt"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func getReceiversPath(addr string) string {
	return fmt.Sprintf(`=~^%s/%s(.*)\z`, addr, "api/v3/receiver")
}

func InitAlertmgrMock(addr string) {
	httpmock.RegisterResponder("GET", addr+"/",
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	httpmock.RegisterResponder("GET", addr,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	httpmock.RegisterResponder("POST", addr+alertmgr.AlertApi,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	httpmock.RegisterResponder("GET", addr+alertmgr.AlertApi,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, make([]interface{}, 0))
		},
	)
	httpmock.RegisterResponder("GET", getReceiversPath(addr),
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, alertmgr.SidecarReceiverConfigs{})
		},
	)
	httpmock.RegisterResponder("POST", getReceiversPath(addr),
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	httpmock.RegisterResponder("DELETE", getReceiversPath(addr),
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}
func testShowAlertReceiver(mcClient *ormclient.Client, uri, token, region, org, name string) ([]ormapi.AlertReceiver, int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	dat := &ormapi.AlertReceiver{}
	dat.Name = name
	dat.AppInst = *in

	recs, status, err := mcClient.ShowAlertReceiver(uri, token)
	return recs, status, err
}

func testCreateAlertReceiver(mcClient *ormclient.Client, uri, token, region, org, name, rType, severity, username, email string) (int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	dat := &ormapi.AlertReceiver{}
	dat.Severity = severity
	dat.Type = rType
	dat.Name = name
	dat.AppInst = *in
	dat.User = username
	dat.Email = email

	status, err := mcClient.CreateAlertReceiver(uri, token, dat)
	return status, err
}

func testDeleteAlertReceiver(mcClient *ormclient.Client, uri, token, region, org, name, rType, severity string) (int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	dat := &ormapi.AlertReceiver{}
	dat.Severity = severity
	dat.Type = rType
	dat.Name = name
	dat.AppInst = *in

	status, err := mcClient.DeleteAlertReceiver(uri, token, dat)
	return status, err

}

func badPermTestAlertReceivers(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	status, err := testCreateAlertReceiver(mcClient, uri, token, region, org, "testAlert", "email", "error", "", "")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	status, err = testDeleteAlertReceiver(mcClient, uri, token, region, org, "testAlert", "email", "error")
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	list, status, err := testShowAlertReceiver(mcClient, uri, token, region, org, "testAlert")
	// we don't take the filter for the show command, so return is just an empty list
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
}

func goodPermTestAlertReceivers(t *testing.T, mcClient *ormclient.Client, uri, devToken, operToken, region, devOrg, operOrg string) {
	// Permissions test
	status, err := testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "", "")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = testDeleteAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	list, status, err := testShowAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// we always return empty result for the unit-test
	require.Equal(t, 0, len(list))

	// missing name check
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "", "email", "error", "", "")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver name has to be specified")
	// invalid receiver name
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "%alertreceiver", "email", "error", "", "")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver name is invalid")
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "al\\!ertreceiver", "email", "error", "", "")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver name is invalid")
	// invalid receiver type check
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "invalid", "error", "", "")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver type invalid")
	// invalid severity check
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "slack", "invalid", "", "")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Alert severity has to be one of")
	// specifying a user in the call - disallowed
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "slack", "error", "user1", "")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "User is not specifiable")
	// invalid receiver email format
	status, err = testCreateAlertReceiver(mcClient, uri, devToken, region, devOrg, "testAlert", "email", "error", "", "xx.com")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Receiver email is invalid")

}
