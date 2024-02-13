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

package deploygen

import (
	"fmt"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestDeploygenBasic(t *testing.T) {
	appSpec := AppSpec{
		Name:      "myapp",
		OrgName:   "myorg",
		Version:   "1.0",
		ImagePath: "docker.io/company/imagename:latest",
		ImageType: "docker",
		ImageHost: "docker.io",
		Command:   "bash",
		Args:      []string{"-c", "echo foobar"},
		Ports: []util.PortSpec{{
			Proto: "tcp",
			Port:  "443",
			Tls:   true,
		}, {
			Proto: "udp",
			Port:  "8001",
			Tls:   true,
		}},
		ScaleWithCluster: true,
	}
	manifest, err := kubeBasic(&appSpec)
	require.Nil(t, err)
	if manifest != basicManifest {
		fmt.Println(manifest)
	}
	require.Equal(t, basicManifest, manifest)
}

var basicManifest = `apiVersion: v1
kind: Service
metadata:
  name: myapp10-tcp
  labels:
    run: myapp1.0
spec:
  type: LoadBalancer
  ports:
  - name: tcp443tls
    protocol: TCP
    port: 443
    targetPort: 443
  selector:
    run: myapp1.0
---
apiVersion: v1
kind: Service
metadata:
  name: myapp10-udp
  labels:
    run: myapp1.0
spec:
  type: LoadBalancer
  ports:
  - name: udp8001tls
    protocol: UDP
    port: 8001
    targetPort: 8001
  selector:
    run: myapp1.0
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: myapp10-deployment
spec:
  selector:
    matchLabels:
      run: myapp1.0
  template:
    metadata:
      labels:
        run: myapp1.0
        mexDeployGen: kubernetes-basic
    spec:
      volumes:
      imagePullSecrets:
      - name: docker.io
      containers:
      - name: myapp10
        image: docker.io/company/imagename:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 443
          protocol: TCP
        - containerPort: 8001
          protocol: UDP
        command:
        - "bash"
        args:
        - "-c"
        - "echo foobar"
`
