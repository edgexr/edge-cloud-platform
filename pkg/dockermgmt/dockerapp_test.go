// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dockermgmt

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/test-go/testify/require"
)

func TestArgsMatchRunning(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	tests := []struct {
		args    []string
		running types.ContainerJSON
		matched bool
	}{{
		[]string{
			"run", "-d", "-l", "edge-cloud", "-l", "mexMetricsEndpoint=127.1.22.46", "--restart=unless-stopped", "--name", "envoyhello1", "--network", "host", "-v", "/home/ubuntu/envoy/certs:/etc/envoy/certs", "-v", "/home/ubuntu/envoy/hello1/access.log:/tmp/access.log", "-v", "/home/ubuntu/envoy/hello1/envoy.yaml:/etc/envoy/envoy.yaml", "ghcr.io/edgexr/envoy-with-curl@sha256:46cbbf3e8e8fb37b7080f360d2eedccfd7709ed49468683f7691645226c2ea96", "envoy", "-c", "/etc/envoy/envoy.yaml", "--use-dynamic-base-id",
		},
		types.ContainerJSON{
			ContainerJSONBase: &types.ContainerJSONBase{
				HostConfig: &container.HostConfig{
					Binds: []string{
						"/home/ubuntu/envoy/certs:/etc/envoy/certs",
						"/home/ubuntu/envoy/hello1/access.log:/tmp/access.log",
						"/home/ubuntu/envoy/hello1/envoy.yaml:/etc/envoy/envoy.yaml",
					},
					NetworkMode: "host",
				},
				Args: []string{
					"envoy", "-c", "/etc/envoy/envoy.yaml", "--use-dynamic-base-id",
				},
			},
			Config: &container.Config{
				Image: "ghcr.io/edgexr/envoy-with-curl@sha256:46cbbf3e8e8fb37b7080f360d2eedccfd7709ed49468683f7691645226c2ea96",
			},
		},
		true,
	}, {
		[]string{"docker", "run", "alpine:latest"},
		types.ContainerJSON{
			Config: &container.Config{
				Image: "alpine:latest",
			},
		},
		true,
	}}
	for _, test := range tests {
		matched := ArgsMatchRunning(ctx, test.running, test.args)
		require.Equal(t, test.matched, matched, fmt.Sprintf("args: %v", test.args))
	}
}
