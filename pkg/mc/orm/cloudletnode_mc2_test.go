// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudletnode.proto

package orm

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/orm/testutil"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
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

func badPermCreateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermCreateCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badCreateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, st, err := testutil.TestPermCreateCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermCreateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermCreateCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionCreateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	out, status, err := testutil.TestPermCreateCloudletNode(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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

func badPermUpdateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermUpdateCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badUpdateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, st, err := testutil.TestPermUpdateCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermUpdateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermUpdateCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionUpdateCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	out, status, err := testutil.TestPermUpdateCloudletNode(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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

func badPermShowCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermShowCloudletNode(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, st, err := testutil.TestPermShowCloudletNode(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermShowCloudletNode(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.CloudletNode)) {
	out, status, err := testutil.TestPermShowCloudletNode(mcClient, uri, token, "bad region", org, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
	require.Equal(t, 0, len(out))
}

var _ = edgeproto.GetFields

func badPermDeleteCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermDeleteCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badDeleteCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, st, err := testutil.TestPermDeleteCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermDeleteCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	_, status, err := testutil.TestPermDeleteCloudletNode(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionDeleteCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	out, status, err := testutil.TestPermDeleteCloudletNode(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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
func badPermTestCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletNode)) {
	badPermCreateCloudletNode(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermUpdateCloudletNode(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermDeleteCloudletNode(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
}
func badPermTestShowCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowCloudletNode(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, showcount int, modFuncs ...func(*edgeproto.CloudletNode)) {
	goodPermCreateCloudletNode(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermUpdateCloudletNode(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermDeleteCloudletNode(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermTestShowCloudletNode(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
	badRegionCreateCloudletNode(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
	badRegionUpdateCloudletNode(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
	badRegionDeleteCloudletNode(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
}
func goodPermTestShowCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowCloudletNode(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowCloudletNode(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestCloudletNode(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, targetCloudlet *edgeproto.CloudletKey, showcount int, modFuncs ...func(*edgeproto.CloudletNode)) {
	badPermTestCloudletNode(t, mcClient, uri, token1, region, org2, targetCloudlet, modFuncs...)
	badPermTestCloudletNode(t, mcClient, uri, token2, region, org1, targetCloudlet, modFuncs...)
	badPermTestShowCloudletNode(t, mcClient, uri, token1, region, org2)
	badPermTestShowCloudletNode(t, mcClient, uri, token2, region, org1)
	goodPermTestCloudletNode(t, mcClient, uri, token1, region, org1, targetCloudlet, showcount, modFuncs...)
	goodPermTestCloudletNode(t, mcClient, uri, token2, region, org2, targetCloudlet, showcount, modFuncs...)
}
