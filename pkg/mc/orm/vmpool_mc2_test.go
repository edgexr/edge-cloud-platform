// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vmpool.proto

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
	_ "github.com/gogo/protobuf/types"
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

func badPermCreateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermCreateVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badCreateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.VMPool)) {
	_, st, err := testutil.TestPermCreateVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermCreateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermCreateVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionCreateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.VMPool)) {
	out, status, err := testutil.TestPermCreateVMPool(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermDeleteVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermDeleteVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badDeleteVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.VMPool)) {
	_, st, err := testutil.TestPermDeleteVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermDeleteVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermDeleteVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionDeleteVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.VMPool)) {
	out, status, err := testutil.TestPermDeleteVMPool(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermUpdateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermUpdateVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badUpdateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.VMPool)) {
	_, st, err := testutil.TestPermUpdateVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermUpdateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermUpdateVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionUpdateVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.VMPool)) {
	out, status, err := testutil.TestPermUpdateVMPool(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermShowVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermShowVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badShowVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.VMPool)) {
	_, st, err := testutil.TestPermShowVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermShowVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	_, status, err := testutil.TestPermShowVMPool(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionShowVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.VMPool)) {
	out, status, err := testutil.TestPermShowVMPool(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermAddVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	_, status, err := testutil.TestPermAddVMPoolMember(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badAddVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.VMPoolMember)) {
	_, st, err := testutil.TestPermAddVMPoolMember(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermAddVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	_, status, err := testutil.TestPermAddVMPoolMember(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionAddVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	out, status, err := testutil.TestPermAddVMPoolMember(mcClient, uri, token, "bad region", org, modFuncs...)
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

func badPermRemoveVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	_, status, err := testutil.TestPermRemoveVMPoolMember(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Forbidden")
	require.Equal(t, http.StatusForbidden, status)
}

func badRemoveVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, status int, modFuncs ...func(*edgeproto.VMPoolMember)) {
	_, st, err := testutil.TestPermRemoveVMPoolMember(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, status, st)
}

func goodPermRemoveVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	_, status, err := testutil.TestPermRemoveVMPoolMember(mcClient, uri, token, region, org, modFuncs...)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func badRegionRemoveVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	out, status, err := testutil.TestPermRemoveVMPoolMember(mcClient, uri, token, "bad region", org, modFuncs...)
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
func badPermTestVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) {
	badPermCreateVMPool(t, mcClient, uri, token, region, org, modFuncs...)
	badPermUpdateVMPool(t, mcClient, uri, token, region, org, modFuncs...)
	badPermDeleteVMPool(t, mcClient, uri, token, region, org, modFuncs...)
}
func badPermTestShowVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string) {
	// show is allowed but won't show anything
	var status int
	var err error
	list0, status, err := testutil.TestPermShowVMPool(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list0))
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.VMPool)) {
	goodPermCreateVMPool(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermUpdateVMPool(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermDeleteVMPool(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermTestShowVMPool(t, mcClient, uri, token, region, org, showcount)
	// make sure region check works
	badRegionCreateVMPool(t, mcClient, uri, token, org, modFuncs...)
	badRegionUpdateVMPool(t, mcClient, uri, token, org, modFuncs...)
	badRegionDeleteVMPool(t, mcClient, uri, token, org, modFuncs...)
}
func goodPermTestShowVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, count int) {
	var status int
	var err error
	list0, status, err := testutil.TestPermShowVMPool(mcClient, uri, token, region, org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, count, len(list0))

	badRegionShowVMPool(t, mcClient, uri, token, org)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestVMPool(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.VMPool)) {
	badPermTestVMPool(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestVMPool(t, mcClient, uri, token2, region, org1, modFuncs...)
	badPermTestShowVMPool(t, mcClient, uri, token1, region, org2)
	badPermTestShowVMPool(t, mcClient, uri, token2, region, org1)
	goodPermTestVMPool(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestVMPool(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}

// This tests the user cannot modify the object because the obj belongs to
// an organization that the user does not have permissions for.
func badPermTestVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) {
	badPermAddVMPoolMember(t, mcClient, uri, token, region, org, modFuncs...)
	badPermRemoveVMPoolMember(t, mcClient, uri, token, region, org, modFuncs...)
}

// This tests the user can modify the object because the obj belongs to
// an organization that the user has permissions for.
func goodPermTestVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token, region, org string, showcount int, modFuncs ...func(*edgeproto.VMPoolMember)) {
	goodPermAddVMPoolMember(t, mcClient, uri, token, region, org, modFuncs...)
	goodPermRemoveVMPoolMember(t, mcClient, uri, token, region, org, modFuncs...)
	// make sure region check works
	badRegionAddVMPoolMember(t, mcClient, uri, token, org, modFuncs...)
	badRegionRemoveVMPoolMember(t, mcClient, uri, token, org, modFuncs...)
}

// Test permissions for user with token1 who should have permissions for
// modifying obj1, and user with token2 who should have permissions for obj2.
// They should not have permissions to modify each other's objects.
func permTestVMPoolMember(t *testing.T, mcClient *mctestclient.Client, uri, token1, token2, region, org1, org2 string, showcount int, modFuncs ...func(*edgeproto.VMPoolMember)) {
	badPermTestVMPoolMember(t, mcClient, uri, token1, region, org2, modFuncs...)
	badPermTestVMPoolMember(t, mcClient, uri, token2, region, org1, modFuncs...)
	goodPermTestVMPoolMember(t, mcClient, uri, token1, region, org1, showcount, modFuncs...)
	goodPermTestVMPoolMember(t, mcClient, uri, token2, region, org2, showcount, modFuncs...)
}
