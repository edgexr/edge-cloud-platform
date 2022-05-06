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
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func testImagePaths(t *testing.T, ctx context.Context, mcClient *mctestclient.Client, uri, tokenAd string) {
	org1 := ormapi.Organization{
		Type: "developer",
		Name: "org1",
	}
	status, err := mcClient.CreateOrg(uri, tokenAd, &org1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	org2 := org1
	org2.Name = "org2"
	status, err = mcClient.CreateOrg(uri, tokenAd, &org2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	org3 := org1
	org3.Name = "org3"
	org3.PublicImages = true
	status, err = mcClient.CreateOrg(uri, tokenAd, &org3)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// non-mobiledgex paths always succeed
	testImagePath(t, ctx, "org1", "http://foobar.com/blah/blah", true)
	testImagePath(t, ctx, "org1", "http://foobar.com/artifactory/repo-blah/blah", true)
	// non-mobiledgex docker path at implied docker.io
	testImagePath(t, ctx, "org1", "library/mongo", true)
	// mobiledgex paths that should succeed - gitlab
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org1/app", true)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org1/app:1.0", true)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org1/app:latest", true)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org1/extra/app:latest", true)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org1/", true)
	// mobiledgex paths that should succeed - artifactory
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/artifactory/repo-org1/cirros-0.4.0-arm-disk.img#md5:7e9cfcb763e83573a4b9d9315f56cc5f", true)
	// public orgs should succeed
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org3/someapp", true)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/artifactory/repo-org3/someapp", true)

	// should fail
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org2/app", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org2/app:1.0", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org2/app:latest", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/artifactory/repo-org2/cirros-0.4.0-arm-disk.img#md5:7e9cfcb763e83573a4b9d9315f56cc5f", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/artifactory/org1/cirros-0.4.0-arm-disk.img#md5:7e9cfcb763e83573a4b9d9315f56cc5f", false)
	// missing orgs should fail
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/org4/someapp", false)
	testImagePath(t, ctx, "org1", "http://foobar.mobiledgex.net/artifactory/repo-org4/someapp", false)
	// docker path which doesn't include http scheme
	testImagePath(t, ctx, "org1", "foobar.mobiledgex.net/andyorg/images/server:1.0", false)
	// test empty org name in both org and path
	testImagePath(t, ctx, "", "docker-qa.mobiledgex.net/", false)

	mobiledgexOrg := ormapi.Organization{
		Type:         "developer",
		Name:         "mobiledgex",
		PublicImages: true,
	}
	status, err = mcClient.CreateOrg(uri, tokenAd, &mobiledgexOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// test publicimages enabled org
	testImagePath(t, ctx, "DeveloperOrg", "docker.mobiledgex.net/mobiledgex/mobiledgex_public/mobiledgexsdkdemo", true)

	testDeleteOrg(t, mcClient, uri, tokenAd, org1.Name)
	testDeleteOrg(t, mcClient, uri, tokenAd, org2.Name)
	testDeleteOrg(t, mcClient, uri, tokenAd, org3.Name)
	testDeleteOrg(t, mcClient, uri, tokenAd, mobiledgexOrg.Name)
}

func testImagePath(t *testing.T, ctx context.Context, org, imagepath string, ok bool) {
	app := edgeproto.App{}
	app.Key.Organization = org
	app.ImagePath = imagepath
	err := checkImagePath(ctx, &app)
	if ok {
		require.Nil(t, err)
	} else {
		require.NotNil(t, err)
		fmt.Printf("%v\n", err)
	}
}
