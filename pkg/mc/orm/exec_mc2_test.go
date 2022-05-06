// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: exec.proto

package orm

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/orm/testutil"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	math "math"
	"net/http"
	"testing"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

var _ = edgeproto.GetFields

func badPermRunCommand(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermRunCommand(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badRunCommand(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, st, err := testutil.TestPermRunCommand(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermRunCommand(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermRunCommand(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionRunCommand(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	out, status, err := testutil.TestPermRunCommand(mcClient, uri, token, "bad region", org, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
	_ = out
}

var _ = edgeproto.GetFields

func badPermRunConsole(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermRunConsole(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badRunConsole(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, st, err := testutil.TestPermRunConsole(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermRunConsole(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermRunConsole(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionRunConsole(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	out, status, err := testutil.TestPermRunConsole(mcClient, uri, token, "bad region", org, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
	_ = out
}

var _ = edgeproto.GetFields

func badPermShowLogs(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermShowLogs(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowLogs(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, st, err := testutil.TestPermShowLogs(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowLogs(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermShowLogs(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowLogs(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	out, status, err := testutil.TestPermShowLogs(mcClient, uri, token, "bad region", org, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
	_ = out
}

var _ = edgeproto.GetFields

func badPermAccessCloudlet(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermAccessCloudlet(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badAccessCloudlet(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, st, err := testutil.TestPermAccessCloudlet(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermAccessCloudlet(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	_, status, err := testutil.TestPermAccessCloudlet(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionAccessCloudlet(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	out, status, err := testutil.TestPermAccessCloudlet(mcClient, uri, token, "bad region", org, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
	_ = out
}

// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTestExecRequest(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ExecRequest)) {
	badPermRunCommand(t, mcClient, uri, token, region, org, modFuncs...)
	badPermRunConsole(t, mcClient, uri, token, region, org, modFuncs...)
	badPermShowLogs(t, mcClient, uri, token, region, org, modFuncs...)
	badPermAccessCloudlet(t, mcClient, uri, token, region, org, modFuncs...)
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestExecRequest(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.ExecRequest)) {
	goodPermRunCommand(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermRunConsole(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermShowLogs(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermAccessCloudlet(t, mcClient, uri, token, region, org, modFuncs...)
	// make sure region check works
	badRegionRunCommand(t, mcClient, uri, token, org, modFuncs...)
	badRegionRunConsole(t, mcClient, uri, token, org, modFuncs...)
	badRegionShowLogs(t, mcClient, uri, token, org, modFuncs...)
	badRegionAccessCloudlet(t, mcClient, uri, token, org, modFuncs...)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestExecRequest(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.ExecRequest)) {
	badPermTestExecRequest(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestExecRequest(t, mcClient, uri, token2, region, org1, modFuncs...)
	goodPermTestExecRequest(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestExecRequest(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}
