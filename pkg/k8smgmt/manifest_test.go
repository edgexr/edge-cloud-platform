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

package k8smgmt

import (
	"context"
	"fmt"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestGenerateAppInstManifest(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	appInst := &testutil.AppInstData()[0]
	app := &testutil.AppData()[0]
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.DeploymentGenerator = ""
	app.EnvVars = map[string]string{
		"SOME_ENV1": "value1",
		"SOME_ENV2": "value2",
	}
	baseMf, err := cloudcommon.GetAppDeploymentManifest(ctx, nil, app)
	require.Nil(t, err)
	app.DeploymentManifest = baseMf
	app.CompatibilityVersion = cloudcommon.GetAppCompatibilityVersion()

	accessApi := &accessapi.TestHandler{}

	app.AllowServerless = true
	ports, err := edgeproto.ParseAppPorts(app.AccessPorts)
	require.Nil(t, err)
	appInst.MappedPorts = ports
	appInst.KubernetesResources = &edgeproto.KubernetesResources{
		GpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(1, 0),
			TotalMemory: 1024,
			TotalOptRes: map[string]string{
				"gpu": "pci:1",
			},
		},
	}
	appInst.CompatibilityVersion = cloudcommon.GetAppInstCompatibilityVersion()
	names, err := GetKubeNames(&edgeproto.ClusterInst{}, app, appInst)
	require.Nil(t, err)
	require.NotEqual(t, "", names.InstanceNamespace)
	names.MultiTenantRestricted = true // add in Network Policy

	mf, err := GenerateAppInstManifest(ctx, accessApi, names, app, appInst)
	require.Nil(t, err)
	if expectedFullManifest != mf {
		fmt.Println(mf)
	}
	require.Equal(t, expectedFullManifest, mf)

	mf, err = GenerateAppInstPolicyManifest(ctx, names, app, appInst)
	require.Nil(t, err)
	if expectedPolicyManifest != mf {
		fmt.Println(mf)
	}
	require.Equal(t, expectedPolicyManifest, mf)
}

var expectedFullManifest = `apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    config: pillimogo1-atlanticinc
    run: pillimogo1.0.0
  name: pillimogo100-http
spec:
  ports:
  - name: http443
    port: 443
    protocol: TCP
    targetPort: 443
  selector:
    run: pillimogo1.0.0
  type: ClusterIP
status:
  loadBalancer: {}
---
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    config: pillimogo1-atlanticinc
    run: pillimogo1.0.0
  name: pillimogo100-tcp
spec:
  ports:
  - name: tcp10002
    port: 10002
    protocol: TCP
    targetPort: 10002
  selector:
    run: pillimogo1.0.0
  type: LoadBalancer
status:
  loadBalancer: {}
---
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    config: pillimogo1-atlanticinc
    run: pillimogo1.0.0
  name: pillimogo100-udp
spec:
  ports:
  - name: udp10002
    port: 10002
    protocol: UDP
    targetPort: 10002
  selector:
    run: pillimogo1.0.0
  type: LoadBalancer
status:
  loadBalancer: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  creationTimestamp: null
  labels:
    config: pillimogo1-atlanticinc
  name: pillimogo100-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      run: pillimogo1.0.0
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        mex-app: pillimogo100-deployment
        mexAppInstName: PillimoGo1
        mexAppInstOrg: AtlanticInc
        mexDeployGen: kubernetes-basic
        run: pillimogo1.0.0
    spec:
      containers:
      - envFrom:
        - configMapRef:
            name: pillimogo1.0.0-envvars
        imagePullPolicy: Always
        name: pillimogo100
        ports:
        - containerPort: 443
          protocol: TCP
        - containerPort: 10002
          protocol: TCP
        - containerPort: 10002
          protocol: UDP
        resources:
          limits:
            cpu: "1"
            memory: 1Gi
            nvidia.com/gpu: "1"
          requests:
            cpu: "1"
            memory: 1Gi
      imagePullSecrets:
      - {}
status: {}
---
apiVersion: v1
data:
  SOME_ENV1: value1
  SOME_ENV2: value2
kind: ConfigMap
metadata:
  creationTimestamp: null
  labels:
    config: pillimogo1-atlanticinc
  name: pillimogo1.0.0-envvars
`

var expectedPolicyManifest = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    config: pillimogo1-atlanticinc
  name: networkpolicy-pillimogo1-atlanticinc
  namespace: pillimogo1-atlanticinc
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: pillimogo1-atlanticinc
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - port: 443
      protocol: TCP
    - port: 10002
      protocol: TCP
    - port: 10002
      protocol: UDP
---
apiVersion: v1
kind: ResourceQuota
metadata:
  labels:
    config: pillimogo1-atlanticinc
  name: pillimogo1-atlanticinc
  namespace: pillimogo1-atlanticinc
spec:
  hard:
    limits.cpu: "1"
    limits.memory: 1Gi
`

var deploymentManifest = `apiVersion: v1
kind: Service
metadata:
  name: pillimogo-tcp
  labels:
    run: pillimogo
spec:
  type: LoadBalancer
  ports:
  - name: http443
    protocol: TCP
    port: 443
    targetPort: 443
  selector:
    run: pillimogo
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pillimogo-deployment
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pillimogo
  template:
    metadata:
      labels:
        app: pillimogo
    spec:
      containers:
      - name: pillimogo
        image: "docker.mobiledgex.net/atlanticinc/images/pillimogo10:1.0.1"
        imagePullPolicy: Always
        ports:
        - containerPort: 443
          protocol: TCP
      - name: pillimogo
        image: "docker.mobiledgex.net/atlanticinc/images/pillimogo11:1.0.1"
        imagePullPolicy: Always
        ports:
        - containerPort: 443
          protocol: TCP
      initContainers:
      - name: pillimogo-init1
        image: "docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils10:1.0.1"
        volumeMounts:
        - mountPath: /data
          name: gh-data
      - name: pillimogo-init2
        image: "docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils11:1.0.1"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: pillimogo2-deployment
spec:
  selector:
    matchLabels:
      run: pillimogo2
  template:
    metadata:
      labels:
        run: pillimogo2
    spec:
      volumes:
      containers:
      - name: pillimogo2
        image: registry.mobiledgex.net/atlanticinc/pillimogo2:1.0
        imagePullPolicy: Always
        ports:
        - containerPort: 10003
          protocol: UDP
      imagePullSecrets:
      - name: registry.mobiledgex.net
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: influxdb
  labels:
    app.kubernetes.io/name: influxdb
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: influxdb
  serviceName: "influxdb"
  template:
    metadata:
      labels:
        app.kubernetes.io/name: influxdb
    spec:
      serviceAccountName: influxdb
      containers:
      - name: influxdb:1.8.0-alpine
        image: "registry-int.mobiledgex.net/atlanticinc/influxdb:1.8.0-alpine"
        imagePullPolicy: "IfNotPresent"`

var expectedDeploymentManifest = `apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    config: ""
    run: pillimogo
  name: pillimogo-tcp
spec:
  ports:
  - name: http443
    port: 443
    protocol: TCP
    targetPort: 443
  selector:
    run: pillimogo
  type: LoadBalancer
status:
  loadBalancer: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  creationTimestamp: null
  labels:
    config: ""
  name: pillimogo-deployment
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pillimogo
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: pillimogo
        mex-app: pillimogo-deployment
        mexAppInstName: PillimoGo1
        mexAppInstOrg: AtlanticInc
    spec:
      containers:
      - image: docker.mobiledgex.net/atlanticinc/images/pillimogo10:1.0.1
        imagePullPolicy: Always
        name: pillimogo
        ports:
        - containerPort: 443
          protocol: TCP
        resources: {}
      - image: docker.mobiledgex.net/atlanticinc/images/pillimogo11:1.0.1
        imagePullPolicy: Always
        name: pillimogo
        ports:
        - containerPort: 443
          protocol: TCP
        resources: {}
      imagePullSecrets:
      - name: docker-test.mobiledgex.net
      - name: docker-int.mobiledgex.net
      - name: docker.mobiledgex.net
      - name: registry.mobiledgex.net
      - name: registry-int.mobiledgex.net
      initContainers:
      - image: docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils10:1.0.1
        name: pillimogo-init1
        resources: {}
        volumeMounts:
        - mountPath: /data
          name: gh-data
      - image: docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils11:1.0.1
        name: pillimogo-init2
        resources: {}
status: {}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  creationTimestamp: null
  labels:
    config: ""
  name: pillimogo2-deployment
spec:
  selector:
    matchLabels:
      run: pillimogo2
  template:
    metadata:
      creationTimestamp: null
      labels:
        mex-app: pillimogo2-deployment
        mexAppInstName: PillimoGo1
        mexAppInstOrg: AtlanticInc
        run: pillimogo2
    spec:
      containers:
      - image: registry.mobiledgex.net/atlanticinc/pillimogo2:1.0
        imagePullPolicy: Always
        name: pillimogo2
        ports:
        - containerPort: 10003
          protocol: UDP
        resources: {}
      imagePullSecrets:
      - name: registry.mobiledgex.net
      - name: docker-test.mobiledgex.net
      - name: docker-int.mobiledgex.net
      - name: docker.mobiledgex.net
      - name: registry-int.mobiledgex.net
  updateStrategy: {}
status:
  currentNumberScheduled: 0
  desiredNumberScheduled: 0
  numberMisscheduled: 0
  numberReady: 0
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: influxdb
    config: ""
  name: influxdb
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: influxdb
  serviceName: influxdb
  template:
    metadata:
      creationTimestamp: null
      labels:
        app.kubernetes.io/name: influxdb
        mex-app: influxdb
        mexAppInstName: PillimoGo1
        mexAppInstOrg: AtlanticInc
    spec:
      containers:
      - image: registry-int.mobiledgex.net/atlanticinc/influxdb:1.8.0-alpine
        imagePullPolicy: IfNotPresent
        name: influxdb:1.8.0-alpine
        resources: {}
      imagePullSecrets:
      - name: docker-test.mobiledgex.net
      - name: docker-int.mobiledgex.net
      - name: docker.mobiledgex.net
      - name: registry.mobiledgex.net
      - name: registry-int.mobiledgex.net
      serviceAccountName: influxdb
  updateStrategy: {}
status:
  availableReplicas: 0
  replicas: 0
`

var imagePaths = map[string]string{
	"docker.mobiledgex.net/atlanticinc/images/pillimogo10:1.0.1":          "docker.mobiledgex.net",
	"docker.mobiledgex.net/atlanticinc/images/pillimogo11:1.0.1":          "docker.mobiledgex.net",
	"docker-test.mobiledgex.net/atlanticinc/images/pillimogo12:1.0.1":     "docker-test.mobiledgex.net",
	"docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils10:1.0.1": "docker-int.mobiledgex.net",
	"docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils11:1.0.1": "docker-int.mobiledgex.net",
	"registry.mobiledgex.net/atlanticinc/pillimogo2:1.0":                  "registry.mobiledgex.net",
	"registry-int.mobiledgex.net/atlanticinc/influxdb:1.8.0-alpine":       "registry-int.mobiledgex.net",
}

func TestImagePullSecrets(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	app := &testutil.AppData()[1]
	app.ImagePath = "docker-test.mobiledgex.net/atlanticinc/images/pillimogo12:1.0.1"
	clusterInst := &testutil.ClusterInstData()[0]
	appInst := &testutil.AppInstData()[0]
	appInst.AppKey = app.Key
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.DeploymentManifest = deploymentManifest

	baseMf, err := cloudcommon.GetAppDeploymentManifest(ctx, nil, app)
	require.Nil(t, err)

	names, err := GetKubeNames(clusterInst, app, appInst)
	require.Nil(t, err)

	for _, imgPath := range names.ImagePaths {
		secret, ok := imagePaths[imgPath]
		require.True(t, ok, fmt.Sprintf("valid image path: %s", imgPath))
		names.ImagePullSecrets = append(names.ImagePullSecrets, secret)
	}

	defaultFlavor := edgeproto.KubernetesResources{
		CpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(1, 0),
			TotalMemory: 1024,
		},
	}
	newMf, err := MergeEnvVars(ctx, nil, app, appInst, baseMf, names.ImagePullSecrets, &KubeNames{}, &defaultFlavor)
	require.Nil(t, err)
	fmt.Println(newMf)
	require.Equal(t, expectedDeploymentManifest, newMf)
}

func TestNames(t *testing.T) {
	// CleanupClusterConfig requires that we can get names for just
	// the ClusterInst without any data in App or AppInst
	_, err := GetKubeNames(&edgeproto.ClusterInst{}, &edgeproto.App{}, &edgeproto.AppInst{})
	require.Nil(t, err)
}
