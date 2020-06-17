package k8smgmt

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

var envVars = `- name: SOME_ENV1
  value: value1
- name: SOME_ENV2
  valueFrom:
    configMapKeyRef:
      key: CloudletName
      name: mexcluster-info
      optional: true
`

func TestEnvVars(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	app := &testutil.AppData[0]
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.DeploymentGenerator = ""
	config := &edgeproto.ConfigFile{
		Kind:   edgeproto.AppConfigEnvYaml,
		Config: envVars,
	}
	app.Configs = append(app.Configs, config)

	// start up http server to serve envVars
	tsEnvVars := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, envVars)
	}))
	defer tsEnvVars.Close()

	// Test Deploymeent manifest with inline EnvVars
	baseMf, err := cloudcommon.GetAppDeploymentManifest(ctx, nil, app)
	require.Nil(t, err)
	envVarsMf, err := MergeEnvVars(ctx, nil, app, baseMf, nil)
	require.Nil(t, err)
	// make envVars remote
	app.Configs[0].Config = tsEnvVars.URL
	remoteEnvVars, err := MergeEnvVars(ctx, nil, app, baseMf, nil)
	require.Nil(t, err)
	require.Equal(t, envVarsMf, remoteEnvVars)
}

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
  replicas: 1
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
      - name: registry.mobiledgex.net`

var expectedDeploymentManifest = `apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
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
  name: pillimogo-deployment
spec:
  replicas: 1
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
        mexAppName: pillimogo
        mexAppVersion: "101"
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
        mexAppName: pillimogo
        mexAppVersion: "101"
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
  updateStrategy: {}
status:
  currentNumberScheduled: 0
  desiredNumberScheduled: 0
  numberMisscheduled: 0
  numberReady: 0
`

var imagePaths = map[string]string{
	"docker.mobiledgex.net/atlanticinc/images/pillimogo10:1.0.1":          "docker.mobiledgex.net",
	"docker.mobiledgex.net/atlanticinc/images/pillimogo11:1.0.1":          "docker.mobiledgex.net",
	"docker-test.mobiledgex.net/atlanticinc/images/pillimogo12:1.0.1":     "docker-test.mobiledgex.net",
	"docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils10:1.0.1": "docker-int.mobiledgex.net",
	"docker-int.mobiledgex.net/atlanticinc/images/pillimogoutils11:1.0.1": "docker-int.mobiledgex.net",
	"registry.mobiledgex.net/atlanticinc/pillimogo2:1.0":                  "registry.mobiledgex.net",
}

func TestImagePullSecrets(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	app := &testutil.AppData[1]
	app.ImagePath = "docker-test.mobiledgex.net/atlanticinc/images/pillimogo12:1.0.1"
	clusterInst := &testutil.ClusterInstData[0]
	appInst := &testutil.AppInstData[0]
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.DeploymentManifest = deploymentManifest

	baseMf, err := cloudcommon.GetAppDeploymentManifest(ctx, nil, app)
	require.Nil(t, err)

	names, err := GetKubeNames(clusterInst, app, appInst)
	require.Nil(t, err)

	for _, imgPath := range names.ImagePaths {
		secret, ok := imagePaths[imgPath]
		require.True(t, ok, "valid image path")
		names.ImagePullSecrets = append(names.ImagePullSecrets, secret)
	}

	newMf, err := MergeEnvVars(ctx, nil, app, baseMf, names.ImagePullSecrets)
	require.Nil(t, err)
	fmt.Println(newMf)
	require.Equal(t, newMf, expectedDeploymentManifest)
}