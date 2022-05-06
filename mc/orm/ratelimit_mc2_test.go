// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ratelimit.proto

package orm

import (
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/orm/testutil"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	_ "github.com/edgexr/edge-cloud/protogen"
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

func badPermShowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.RateLimitSettings)) {
	_, status, err := testutil.TestPermShowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.RateLimitSettings)) {
	_, st, err := testutil.TestPermShowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.RateLimitSettings)) {
	_, status, err := testutil.TestPermShowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.RateLimitSettings)) {
	out, status, err := testutil.TestPermShowRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermCreateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermCreateFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badCreateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, st, err := testutil.TestPermCreateFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermCreateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermCreateFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionCreateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	out, status, err := testutil.TestPermCreateFlowRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermUpdateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermUpdateFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badUpdateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, st, err := testutil.TestPermUpdateFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermUpdateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermUpdateFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionUpdateFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	out, status, err := testutil.TestPermUpdateFlowRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermDeleteFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermDeleteFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badDeleteFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, st, err := testutil.TestPermDeleteFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermDeleteFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermDeleteFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionDeleteFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	out, status, err := testutil.TestPermDeleteFlowRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermShowFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermShowFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, st, err := testutil.TestPermShowFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	_, status, err := testutil.TestPermShowFlowRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	out, status, err := testutil.TestPermShowFlowRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermCreateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermCreateMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badCreateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, st, err := testutil.TestPermCreateMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermCreateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermCreateMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionCreateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	out, status, err := testutil.TestPermCreateMaxReqsRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermUpdateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermUpdateMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badUpdateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, st, err := testutil.TestPermUpdateMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermUpdateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermUpdateMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionUpdateMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	out, status, err := testutil.TestPermUpdateMaxReqsRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermDeleteMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermDeleteMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badDeleteMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, st, err := testutil.TestPermDeleteMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermDeleteMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermDeleteMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionDeleteMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	out, status, err := testutil.TestPermDeleteMaxReqsRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermShowMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermShowMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, st, err := testutil.TestPermShowMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	_, status, err := testutil.TestPermShowMaxReqsRateLimitSettings(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	out, status, err := testutil.TestPermShowMaxReqsRateLimitSettings(mcClient, uri, token, "bad region", org, modFuncs...)
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
func badPermTestFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	badPermCreateFlowRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	badPermUpdateFlowRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	badPermDeleteFlowRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
}
func badPermTestShowFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowFlowRateLimitSettings(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	goodPermCreateFlowRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermUpdateFlowRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermDeleteFlowRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermTestShowFlowRateLimitSettings(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
	badRegionCreateFlowRateLimitSettings(t, mcClient, uri, token, org, modFuncs...)
	badRegionUpdateFlowRateLimitSettings(t, mcClient, uri, token, org, modFuncs...)
	badRegionDeleteFlowRateLimitSettings(t, mcClient, uri, token, org, modFuncs...)
}
func goodPermTestShowFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowFlowRateLimitSettings(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowFlowRateLimitSettings(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestFlowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) {
	badPermTestFlowRateLimitSettings(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestFlowRateLimitSettings(t, mcClient, uri, token2, region, org1, modFuncs...)
	badPermTestShowFlowRateLimitSettings(t, mcClient, uri, token1, region, org2)
	badPermTestShowFlowRateLimitSettings(t, mcClient, uri, token2, region, org1)
	goodPermTestFlowRateLimitSettings(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestFlowRateLimitSettings(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}

// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTestMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	badPermCreateMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	badPermUpdateMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	badPermDeleteMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
}
func badPermTestShowMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowMaxReqsRateLimitSettings(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	goodPermCreateMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermUpdateMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermDeleteMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermTestShowMaxReqsRateLimitSettings(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
	badRegionCreateMaxReqsRateLimitSettings(t, mcClient, uri, token, org, modFuncs...)
	badRegionUpdateMaxReqsRateLimitSettings(t, mcClient, uri, token, org, modFuncs...)
	badRegionDeleteMaxReqsRateLimitSettings(t, mcClient, uri, token, org, modFuncs...)
}
func goodPermTestShowMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowMaxReqsRateLimitSettings(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowMaxReqsRateLimitSettings(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestMaxReqsRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) {
	badPermTestMaxReqsRateLimitSettings(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestMaxReqsRateLimitSettings(t, mcClient, uri, token2, region, org1, modFuncs...)
	badPermTestShowMaxReqsRateLimitSettings(t, mcClient, uri, token1, region, org2)
	badPermTestShowMaxReqsRateLimitSettings(t, mcClient, uri, token2, region, org1)
	goodPermTestMaxReqsRateLimitSettings(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestMaxReqsRateLimitSettings(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}

func badPermTestShowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowRateLimitSettings(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.RateLimitSettings)) {
	goodPermTestShowRateLimitSettings(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
}
func goodPermTestShowRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowRateLimitSettings(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowRateLimitSettings(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestRateLimitSettings(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.RateLimitSettings)) {
	badPermTestShowRateLimitSettings(t, mcClient, uri, token1, region, org2)
	badPermTestShowRateLimitSettings(t, mcClient, uri, token2, region, org1)
	goodPermTestRateLimitSettings(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestRateLimitSettings(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}
