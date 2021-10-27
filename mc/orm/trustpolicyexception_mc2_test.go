// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicyexception.proto

package orm

import (
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/testutil"
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

func badPermCreateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermCreateTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badCreateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, st, err := testutil.TestPermCreateTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermCreateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermCreateTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionCreateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	out, status, err := testutil.TestPermCreateTrustPolicyException(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermUpdateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermUpdateTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badUpdateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, st, err := testutil.TestPermUpdateTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermUpdateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermUpdateTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionUpdateTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	out, status, err := testutil.TestPermUpdateTrustPolicyException(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermDeleteTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermDeleteTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badDeleteTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, st, err := testutil.TestPermDeleteTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermDeleteTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermDeleteTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionDeleteTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	out, status, err := testutil.TestPermDeleteTrustPolicyException(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermShowTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermShowTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, st, err := testutil.TestPermShowTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	_, status, err := testutil.TestPermShowTrustPolicyException(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	out, status, err := testutil.TestPermShowTrustPolicyException(mcClient, uri, token, "bad region", org, modFuncs...)
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
func badPermTestTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	badPermCreateTrustPolicyException(t, mcClient, uri, token, region, org, modFuncs...)
	badPermUpdateTrustPolicyException(t, mcClient, uri, token, region, org, modFuncs...)
	badPermDeleteTrustPolicyException(t, mcClient, uri, token, region, org, modFuncs...)
}
func badPermTestShowTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowTrustPolicyException(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	goodPermCreateTrustPolicyException(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermUpdateTrustPolicyException(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermDeleteTrustPolicyException(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermTestShowTrustPolicyException(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
	badRegionCreateTrustPolicyException(t, mcClient, uri, token, org, modFuncs...)
	badRegionUpdateTrustPolicyException(t, mcClient, uri, token, org, modFuncs...)
	badRegionDeleteTrustPolicyException(t, mcClient, uri, token, org, modFuncs...)
}
func goodPermTestShowTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowTrustPolicyException(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowTrustPolicyException(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestTrustPolicyException(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.TrustPolicyException)) {
	badPermTestTrustPolicyException(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestTrustPolicyException(t, mcClient, uri, token2, region, org1, modFuncs...)
	badPermTestShowTrustPolicyException(t, mcClient, uri, token1, region, org2)
	badPermTestShowTrustPolicyException(t, mcClient, uri, token2, region, org1)
	goodPermTestTrustPolicyException(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestTrustPolicyException(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}
