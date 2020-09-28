// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

package orm

import (
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/testutil"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
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

func badPermCreateClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermCreateClusterInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermCreateClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermCreateClusterInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

var _ = edgeproto.GetFields

func badPermDeleteClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermDeleteClusterInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermDeleteClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermDeleteClusterInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

var _ = edgeproto.GetFields

func badPermUpdateClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermUpdateClusterInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermUpdateClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermUpdateClusterInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

var _ = edgeproto.GetFields

func badPermShowClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermShowClusterInst(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func goodPermShowClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ClusterInst)) {
	_, status, err := testutil.TestPermShowClusterInst(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTestClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.ClusterInst)) {
	badPermCreateClusterInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermUpdateClusterInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermDeleteClusterInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
}

func badPermTestShowClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	list, status, err := testutil.TestPermShowClusterInst(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, showcount int, modFuncs ...func(*edgeproto.ClusterInst)) {
	goodPermCreateClusterInst(t, mcClient, uri, token, region, org, targetCloudlet)
	goodPermUpdateClusterInst(t, mcClient, uri, token, region, org, targetCloudlet)
	goodPermDeleteClusterInst(t, mcClient, uri, token, region, org, targetCloudlet)

	// make sure region check works
	_, status, err := testutil.TestPermCreateClusterInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	_, status, err = testutil.TestPermUpdateClusterInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	_, status, err = testutil.TestPermDeleteClusterInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)

	goodPermTestShowClusterInst(t, mcClient, uri, token, region, org, showcount)
}

func goodPermTestShowClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, count int) {
	list, status, err := testutil.TestPermShowClusterInst(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list))

	// make sure region check works
	list, status, err = testutil.TestPermShowClusterInst(mcClient, uri, token, "bad region", org)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "\"bad region\" not found")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 0, len(list))
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestClusterInst(t *testing.T, mcClient *ormclient.Client, uri, token1, token2, region, org1, org2 string, targetCloudlet *edgeproto.CloudletKey, showcount int, modFuncs ...func(*edgeproto.ClusterInst)) {
	badPermTestClusterInst(t, mcClient, uri, token1, region, org2, targetCloudlet, modFuncs...)
	badPermTestShowClusterInst(t, mcClient, uri, token1, region, org2)
	badPermTestClusterInst(t, mcClient, uri, token2, region, org1, targetCloudlet, modFuncs...)
	badPermTestShowClusterInst(t, mcClient, uri, token2, region, org1)

	goodPermTestClusterInst(t, mcClient, uri, token1, region, org1, targetCloudlet, showcount, modFuncs...)
	goodPermTestClusterInst(t, mcClient, uri, token2, region, org2, targetCloudlet, showcount, modFuncs...)
}
