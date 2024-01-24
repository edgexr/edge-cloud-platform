// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinst.proto

package orm

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
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

func badPermCreateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermCreateAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badCreateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, st, err := testutil.TestPermCreateAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermCreateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermCreateAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionCreateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	out, status, err := testutil.TestPermCreateAppInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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

func badPermDeleteAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermDeleteAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badDeleteAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, st, err := testutil.TestPermDeleteAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermDeleteAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermDeleteAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionDeleteAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	out, status, err := testutil.TestPermDeleteAppInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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

func badPermRefreshAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermRefreshAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badRefreshAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, st, err := testutil.TestPermRefreshAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermRefreshAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermRefreshAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionRefreshAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	out, status, err := testutil.TestPermRefreshAppInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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

func badPermUpdateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermUpdateAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badUpdateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, st, err := testutil.TestPermUpdateAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermUpdateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermUpdateAppInst(mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionUpdateAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	out, status, err := testutil.TestPermUpdateAppInst(mcClient, uri, token, "bad region", org, targetCloudlet, modFuncs...)
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

func badPermShowAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermShowAppInst(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.AppInst)) {
	_, st, err := testutil.TestPermShowAppInst(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppInst)) {
	_, status, err := testutil.TestPermShowAppInst(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.AppInst)) {
	out, status, err := testutil.TestPermShowAppInst(mcClient, uri, token, "bad region", org, modFuncs...)
	require.NotNil(t, err)
	if err.Error() == "Forbidden" {
		require.Equal(t, http.StatusForbidden, status)
	} else {
		require.Contains(t, err.Error(), "\"bad region\" not found")
		require.Equal(t, http.StatusBadRequest, status)
	}
	require.Equal(t, 0, len(out))
}

// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTestAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.AppInst)) {
	badPermCreateAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermRefreshAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermUpdateAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	badPermDeleteAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
}
func badPermTestShowAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowAppInst(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, targetCloudlet *edgeproto.CloudletKey, showcount int, modFuncs ...func(*edgeproto.AppInst)) {
	goodPermCreateAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermRefreshAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermUpdateAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermDeleteAppInst(t, mcClient, uri, token, region, org, targetCloudlet, modFuncs...)
	goodPermTestShowAppInst(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
	badRegionCreateAppInst(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
	badRegionRefreshAppInst(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
	badRegionUpdateAppInst(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
	badRegionDeleteAppInst(t, mcClient, uri, token, org, targetCloudlet, modFuncs...)
}
func goodPermTestShowAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowAppInst(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowAppInst(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestAppInst(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, targetCloudlet *edgeproto.CloudletKey, showcount int, modFuncs ...func(*edgeproto.AppInst)) {
	badPermTestAppInst(t, mcClient, uri, token1, region, org2, targetCloudlet, modFuncs...)
	badPermTestAppInst(t, mcClient, uri, token2, region, org1, targetCloudlet, modFuncs...)
	badPermTestShowAppInst(t, mcClient, uri, token1, region, org2)
	badPermTestShowAppInst(t, mcClient, uri, token2, region, org1)
	goodPermTestAppInst(t, mcClient, uri, token1, region, org1, targetCloudlet, showcount, modFuncs...)
	goodPermTestAppInst(t, mcClient, uri, token2, region, org2, targetCloudlet, showcount, modFuncs...)
}

var _ = edgeproto.GetFields

func badPermRequestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppInstLatency)) {
	_, status, err := testutil.TestPermRequestAppInstLatency(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badRequestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.AppInstLatency)) {
	_, st, err := testutil.TestPermRequestAppInstLatency(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermRequestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppInstLatency)) {
	_, status, err := testutil.TestPermRequestAppInstLatency(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionRequestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.AppInstLatency)) {
	out, status, err := testutil.TestPermRequestAppInstLatency(mcClient, uri, token, "bad region", org, modFuncs...)
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
func badPermTestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppInstLatency)) {
	badPermRequestAppInstLatency(t, mcClient, uri, token, region, org, modFuncs...)
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.AppInstLatency)) {
	goodPermRequestAppInstLatency(t, mcClient, uri, token, region, org, modFuncs...)
	// make sure region check works
	badRegionRequestAppInstLatency(t, mcClient, uri, token, org, modFuncs...)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestAppInstLatency(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.AppInstLatency)) {
	badPermTestAppInstLatency(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestAppInstLatency(t, mcClient, uri, token2, region, org1, modFuncs...)
	goodPermTestAppInstLatency(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestAppInstLatency(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}
