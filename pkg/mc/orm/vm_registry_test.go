package orm

import (
	"context"
	"net/http"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"github.com/stretchr/testify/require"
)

func vmRegDeleteTestData(t *testing.T, ctx context.Context, entries []entry, regAuthMgr *cloudcommon.RegistryAuthMgr) {
	for _, v := range entries {
		if v.OrgType == OrgTypeOperator {
			continue
		}
		err := regAuthMgr.DeleteRegistryAuth(ctx, serverConfig.VmRegistryAddr, v.Org)
		require.Nil(t, err)

		auth, err := vmRegistryGetPullKey(ctx, v.Org)
		require.Nil(t, err)
		require.Equal(t, cloudcommon.NoAuth, auth.AuthType, auth)
	}
}

func vmRegVerifyTestData(t *testing.T, ctx context.Context, entries []entry) {
	// admin key must always exist
	adminAuth, err := getVmRegAdminAuth(ctx)
	require.Nil(t, err)
	require.Equal(t, cloudcommon.BasicAuth, adminAuth.AuthType)
	require.NotNil(t, adminAuth.Username)
	require.NotNil(t, adminAuth.Password)

	for _, v := range entries {
		if v.OrgType == OrgTypeOperator {
			continue
		}
		auth, err := vmRegistryGetPullKey(ctx, v.Org)
		require.Nil(t, err)
		require.Equal(t, cloudcommon.TokenAuth, auth.AuthType)
		require.Equal(t, adminAuth.Username, auth.Username)
		require.NotEmpty(t, auth.Token)
	}
}

func vmRegVerifyPullKeyPerms(t *testing.T, ctx context.Context, org, otherOrg string, mcClient *mctestclient.Client, uri string) {
	auth, err := vmRegistryGetPullKey(ctx, org)
	require.Nil(t, err)
	require.Equal(t, cloudcommon.TokenAuth, auth.AuthType)
	require.NotEmpty(t, auth.Username)
	require.NotEmpty(t, auth.Token)
	// check auth scopes
	scopes, status, err := mcClient.AuthScopes(uri, auth.Token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []ormapi.AuthScope{{
		Resource: ResourceArtifacts,
		Action:   ActionManage,
	}, {
		Resource: ResourceArtifacts,
		Action:   ActionView,
	}}, scopes)
	// verify authorization, this mimics auth query that
	// would be sent by the VM Registry service.
	scope := ormapi.AuthScope{
		Org:      org,
		Resource: ResourceArtifacts,
		Action:   ActionView,
		Object:   "some object", // should be ignored
	}
	status, err = mcClient.UserAuthorized(uri, auth.Token, &scope)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// verify lack of auth for other objects
	scopeBad := scope
	scopeBad.Resource = ResourceFlavors
	status, err = mcClient.UserAuthorized(uri, auth.Token, &scopeBad)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// verify lack of auth for other org
	scopeBad = scope
	scopeBad.Org = otherOrg
	status, err = mcClient.UserAuthorized(uri, auth.Token, &scopeBad)
	require.NotNil(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
	// verify lack of auth for empty org
	scopeBad = scope
	scopeBad.Org = ""
	status, err = mcClient.UserAuthorized(uri, auth.Token, &scopeBad)
	require.NotNil(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
	// CRM needs to be able to delete OVF files, so it
	// needs write access.
	scope.Action = ActionManage
	status, err = mcClient.UserAuthorized(uri, auth.Token, &scope)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}
