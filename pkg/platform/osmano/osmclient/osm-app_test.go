// Copyright 2025 EdgeXR, Inc
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

package osmclient

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/deploygen"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/test-go/testify/require"
)

func getTestApp(t *testing.T) *edgeproto.App {
	app := edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         "testApp",
			Organization: "devorg",
			Version:      "1.0",
		},
		Deployment:  cloudcommon.DeploymentTypeKubernetes,
		ImagePath:   "docker.io/nginxdemos/hello:0.4",
		AccessPorts: "http:80:tls",
		KubernetesResources: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 200,
			},
		},
		AllowServerless: true,
	}
	app.DeploymentGenerator = deploygen.KubernetesBasic
	manifest, err := cloudcommon.GenerateManifest(&app)
	require.Nil(t, err)
	app.DeploymentManifest = manifest
	return &app
}

func TestCreateAppArchive(t *testing.T) {
	app := getTestApp(t)
	out, err := createAppArchive(app)
	require.Nil(t, err)

	buf := bytes.Buffer{}
	rdr, err := gzip.NewReader(bytes.NewReader(out))
	require.Nil(t, err)
	_, err = buf.ReadFrom(rdr)
	require.Nil(t, err)

	trdr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	for {
		hdr, err := trdr.Next()
		if err == io.EOF {
			break
		}
		require.Equal(t, tar.TypeReg, int32(hdr.Typeflag))

		dat, err := io.ReadAll(trdr)
		require.Nil(t, err)
		fmt.Printf("File %s:\n", hdr.Name)
		fmt.Println(string(dat))
		require.Nil(t, err)
	}
}

func TestAddOKA(t *testing.T) {
	client := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	app := getTestApp(t)
	_, err := client.CreateApp(ctx, app)
	require.Nil(t, err)
}

func TestDeleteOKA(t *testing.T) {
	client := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	app := getTestApp(t)
	err := client.DeleteApp(ctx, app)
	require.Nil(t, err)
}

func TestGetOKA(t *testing.T) {
	client := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	//app := getTestApp(t)
	oka, err := client.GetApp(ctx, "testapp2")
	require.Nil(t, err)
	fmt.Println(oka)
}
