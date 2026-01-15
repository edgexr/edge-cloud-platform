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

package controller

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestAppApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)
	cplookup := &svcnode.ZonePoolCache{}
	cplookup.Init()
	nodeMgr.ZonePoolLookup = cplookup

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	// create support data
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())

	testutil.InternalAppTest(t, "cud", apis.appApi, testutil.CreatedAppData())

	testAppResourceConsistency(t, ctx, apis)

	// update should validate ports
	upapp := testutil.AppData()[3]
	upapp.AccessPorts = "tcp:0"
	upapp.Fields = []string{edgeproto.AppFieldAccessPorts}
	_, err := apis.appApi.UpdateApp(ctx, &upapp)
	require.NotNil(t, err, "Update app with port 0")
	require.Contains(t, err.Error(), "App ports out of range")

	// update should also validate skipHcPorts
	upapp = testutil.AppData()[3]
	upapp.SkipHcPorts = "tcp:8080"
	upapp.Fields = []string{edgeproto.AppFieldSkipHcPorts}
	_, err = apis.appApi.UpdateApp(ctx, &upapp)
	require.Nil(t, err, "Update app with SkipHcPort 8080")
	obj := testutil.AppData()[3]
	_, err = apis.appApi.DeleteApp(ctx, &obj)
	require.Nil(t, err)

	// validateSkipHcPorts
	obj = testutil.AppData()[2]
	obj.SkipHcPorts = "udp:11111"
	obj.Fields = []string{edgeproto.AppFieldSkipHcPorts}
	_, err = apis.appApi.UpdateApp(ctx, &obj)
	require.NotNil(t, err, "update App with udp skipHcPort")
	require.Contains(t, err.Error(), "Protocol L_PROTO_UDP unsupported for healthchecks")

	obj = testutil.AppData()[2]
	obj.SkipHcPorts = "tcp:444"
	obj.Fields = []string{edgeproto.AppFieldSkipHcPorts}
	_, err = apis.appApi.UpdateApp(ctx, &obj)
	require.NotNil(t, err, "Update App with skipHcPort not in AccessPorts")
	require.Contains(t, err.Error(), "skipHcPort 444 not found in accessPorts")

	obj = testutil.AppData()[8]
	obj.SkipHcPorts = "tcp:5000-5004"
	obj.Fields = []string{edgeproto.AppFieldSkipHcPorts}
	_, err = apis.appApi.UpdateApp(ctx, &obj)
	require.NotNil(t, err, "Update App with skipHcPort range not in AccessPorts")
	require.Contains(t, err.Error(), "skipHcPort 5003 not found in accessPorts")

	obj = testutil.AppData()[8]
	obj.SkipHcPorts = "tcp:5000-5002"
	obj.Fields = []string{edgeproto.AppFieldSkipHcPorts}
	_, err = apis.appApi.UpdateApp(ctx, &obj)
	require.Nil(t, err, "Update App with skipHcPort range")

	// image path is optional for docker deployments if
	// deployment manifest is specified.
	appFlavor := testutil.FlavorData()[2]
	app := edgeproto.App{
		Key: edgeproto.AppKey{
			Organization: "org",
			Name:         "someapp",
			Version:      "1.0.1",
		},
		ImageType:          edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:        "tcp:445,udp:1212",
		Deployment:         "docker", // avoid trying to parse k8s manifest
		DeploymentManifest: "some manifest",
		NodeResources:      &edgeproto.NodeResources{},
	}
	app.NodeResources.SetFromFlavor(&appFlavor)

	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err, "Create app with deployment manifest")
	checkApp := edgeproto.App{}
	found := apis.appApi.Get(&app.Key, &checkApp)
	require.True(t, found, "found app")
	require.Equal(t, "", checkApp.ImagePath, "image path empty")
	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err)

	// manifest must be empty if deployment is helm
	app.Deployment = cloudcommon.DeploymentTypeHelm
	app.DeploymentManifest = testK8SManifest1
	app.NodeResources = nil
	app.KubernetesResources = &edgeproto.KubernetesResources{}
	app.KubernetesResources.SetFromFlavor(&testutil.FlavorData()[2])
	app.ImageType = edgeproto.ImageType_IMAGE_TYPE_HELM
	app.ImagePath = "https://myhelmrepo/charts:mycharts/myhelmapp"
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Manifest is not used for Helm deployments")
	// check that creation passes with empty manifest
	app.DeploymentManifest = ""
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err)
	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err)

	// user-specified manifest parsing/consistency/checking
	app.Deployment = "kubernetes"
	app.DeploymentManifest = testK8SManifest1
	app.ImageType = edgeproto.ImageType_IMAGE_TYPE_DOCKER
	app.AccessPorts = "tcp:80"
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err)
	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err)

	// empty config check (edgecloud-3993)
	app.Configs = []*edgeproto.ConfigFile{
		&edgeproto.ConfigFile{
			Kind: edgeproto.AppConfigEnvYaml,
		},
	}
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Empty config for config kind")

	// test Updating of the ports with a manifest k8s. Manifest should be cleared
	k8sApp := testutil.AppData()[2]
	// clean up previous instance first
	_, err = apis.appApi.DeleteApp(ctx, &k8sApp)
	require.Nil(t, err)

	k8sApp = testutil.AppData()[2]
	k8sApp.Deployment = cloudcommon.DeploymentTypeKubernetes
	k8sApp.DeploymentManifest = testK8SManifest1
	k8sApp.AccessPorts = "tcp:80"
	_, err = apis.appApi.CreateApp(ctx, &k8sApp)
	require.Nil(t, err)
	// Update ports with a manifest and verify it requires an update to the manifest
	k8sApp.AccessPorts = "tcp:80,tcp:81"
	k8sApp.Fields = []string{edgeproto.AppFieldAccessPorts}
	_, err = apis.appApi.UpdateApp(ctx, &k8sApp)
	require.NotNil(t, err, "k8s app with manifest should complain about the manifest")
	require.Contains(t, "kubernetes manifest which was previously specified must be provided again when changing access ports",
		err.Error())

	vmApp := testutil.AppData()[3]
	vmApp.Deployment = cloudcommon.DeploymentTypeVM
	vmApp.DeploymentManifest = testVmManifest
	vmApp.AccessPorts = "tcp:80"
	_, err = apis.appApi.CreateApp(ctx, &vmApp)
	require.Nil(t, err)
	vmApp.AccessPorts = "tcp:80,tcp:81"
	vmApp.Fields = []string{edgeproto.AppFieldAccessPorts}
	// Update of the VM app with a manifest and make sure that manifest is retained
	_, err = apis.appApi.UpdateApp(ctx, &vmApp)
	require.Nil(t, err, "Vm app should be updated with no error")
	storedApp := edgeproto.App{}
	found = apis.appApi.Get(vmApp.GetKey(), &storedApp)
	require.True(t, found, "VM app should still be in etcd after update")
	require.Equal(t, testVmManifest, storedApp.DeploymentManifest, "Deployment manifest should not be affected by access port update")

	// accessports with `maxpktsize`
	app.Key.Name = "k8sapp"
	app.Deployment = "kubernetes"
	app.AccessPorts = "tcp:888,udp:1999:maxpktsize=1500"
	app.DeploymentManifest = ""
	app.Configs = nil
	app.ImageType = edgeproto.ImageType_IMAGE_TYPE_DOCKER
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err, "Create app with maxpktsize")
	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err)
	app.AccessPorts = "tcp:888,tcp:1999:maxpktsize=1500"
	// maxpktsize is not valid config for TCP port
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.NotNil(t, err, "Create app with maxpktsize fails")

	app.Key.Name = "dockapp"
	app.Deployment = "docker"
	app.AccessPorts = "tcp:888,udp:1999:maxpktsize=1500"
	app.ImageType = edgeproto.ImageType_IMAGE_TYPE_DOCKER
	app.KubernetesResources = nil
	app.NodeResources = &edgeproto.NodeResources{}
	app.NodeResources.SetFromFlavor(&appFlavor)
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err, "Create app with maxpktsize")
	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err)
	app.AccessPorts = "tcp:888,udp:1999:maxpktsize=1500000"
	// maxpktsize should be less than equal 50000
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.NotNil(t, err, "Create app with maxpktsize fails")

	// test updating kubernetes resources
	app.Deployment = "kubernetes"
	app.AccessPorts = "tcp:888"
	app.DefaultFlavor.Name = ""
	app.KubernetesResources = &edgeproto.KubernetesResources{
		CpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(1, 0),
			TotalMemory: 1024,
		},
		GpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(2, 0),
			TotalMemory: 2048,
			TotalOptRes: map[string]string{
				"gpu": "pci:1",
			},
		},
	}
	app.NodeResources = nil
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err)
	// check created
	err = app.KubernetesResources.Validate()
	found = apis.appApi.Get(app.GetKey(), &storedApp)
	require.True(t, found)
	require.Nil(t, err)
	require.Equal(t, app.KubernetesResources, storedApp.KubernetesResources)
	// update resources
	updateApp := &edgeproto.App{}
	updateApp.Key = app.Key
	updateApp.KubernetesResources = &edgeproto.KubernetesResources{
		CpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(1, 500*edgeproto.DecMillis),
			TotalMemory: 1234,
		},
		GpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(2, 500*edgeproto.DecMillis),
			TotalMemory: 2456,
			TotalOptRes: map[string]string{
				"gpu": "pci:1",
			},
		},
	}
	updateApp.Fields = []string{
		edgeproto.AppFieldKubernetesResources,
	}
	_, err = apis.appApi.UpdateApp(ctx, updateApp)
	require.Nil(t, err)
	// check updated
	err = updateApp.KubernetesResources.Validate()
	require.Nil(t, err)
	found = apis.appApi.Get(app.GetKey(), &storedApp)
	require.True(t, found)
	require.Equal(t, updateApp.KubernetesResources, storedApp.KubernetesResources)
	// update single value
	updateApp = &edgeproto.App{}
	updateApp.Key = app.Key
	updateApp.KubernetesResources = &edgeproto.KubernetesResources{
		CpuPool: &edgeproto.NodePoolResources{
			TotalMemory: 4096,
		},
	}
	// compare entire resources to ensure only 1 value changed
	updatedResources := storedApp.KubernetesResources.Clone()
	updatedResources.CpuPool.TotalMemory = updateApp.KubernetesResources.CpuPool.TotalMemory
	updateApp.Fields = []string{
		edgeproto.AppFieldKubernetesResourcesCpuPoolTotalMemory,
	}
	_, err = apis.appApi.UpdateApp(ctx, updateApp)
	require.Nil(t, err)
	// check updated
	storedApp = edgeproto.App{}
	found = apis.appApi.Get(app.GetKey(), &storedApp)
	require.True(t, found)
	require.Equal(t, updatedResources, storedApp.KubernetesResources)

	// clean up app
	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err)

	app = testutil.AppData()[12]
	require.Equal(t, app.Deployment, cloudcommon.DeploymentTypeVM)
	app.Key.Name = "vm k8s"
	app.KubernetesResources = &edgeproto.KubernetesResources{}
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "cannot specify Kubernetes resources for vm deployment")

	app = testutil.AppData()[15]
	require.Equal(t, app.Deployment, cloudcommon.DeploymentTypeDocker)
	app.Key.Name = "docker k8s"
	app.KubernetesResources = &edgeproto.KubernetesResources{}
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "cannot specify Kubernetes resources for docker deployment")

	// Verify that qossessionduration cannot be specified without also specifying a qossessionprofile
	qosApp := testutil.AppData()[15]
	require.Equal(t, app.Deployment, cloudcommon.DeploymentTypeDocker)
	qosApp.Key.Name = "docker serverless"
	qosApp.QosSessionDuration = 60
	_, err = apis.appApi.CreateApp(ctx, &qosApp)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "QosSessionDuration cannot be specified without setting QosSessionProfile")
	// Verify success case
	qosApp.QosSessionProfile = edgeproto.QosSessionProfile_QOS_THROUGHPUT_DOWN_M
	_, err = apis.appApi.CreateApp(ctx, &qosApp)
	require.Nil(t, err, "Create app with proper QOS Priority Sessions config")

	// test updating app with a list of alertpolicies
	alertPolicyApp := testutil.AppData()[1]
	alertPolicyApp.Deployment = cloudcommon.DeploymentTypeKubernetes
	_, err = apis.appApi.DeleteApp(ctx, &alertPolicyApp)
	require.Nil(t, err, "Deleted old app")
	_, err = apis.appApi.CreateApp(ctx, &alertPolicyApp)
	require.Nil(t, err, "Create app without policies")
	// get the revision
	found = apis.appApi.Get(alertPolicyApp.GetKey(), &storedApp)
	require.True(t, found, "Found app")
	rev := storedApp.Revision
	// update with alert policy - should fail, no alert policies
	upapp = alertPolicyApp
	upapp.AlertPolicies = []string{testutil.AlertPolicyData()[0].Key.Name}
	upapp.Fields = []string{edgeproto.AppFieldAlertPolicies}
	_, err = apis.appApi.UpdateApp(ctx, &upapp)
	require.NotNil(t, err, "Update with a non-existent alert policy")
	// create alert policy
	userAlert := testutil.AlertPolicyData()[0]
	_, err = apis.alertPolicyApi.CreateAlertPolicy(ctx, &userAlert)
	require.Nil(t, err, "Create Alert policy")
	// update app with existing alert policy
	_, err = apis.appApi.UpdateApp(ctx, &upapp)
	require.Nil(t, err, "Update with an alert policy")
	// get the revision
	found = apis.appApi.Get(alertPolicyApp.GetKey(), &storedApp)
	require.True(t, found, "Found app")
	// new revision should be the same as the old one
	require.Equal(t, rev, storedApp.Revision, "Revions is not updated for updated list of alert policies")
	// clean up
	_, err = apis.appApi.DeleteApp(ctx, &alertPolicyApp)
	require.Nil(t, err, "Deleted app with alert policy")
	_, err = apis.alertPolicyApi.DeleteAlertPolicy(ctx, &userAlert)
	require.Nil(t, err, "Delete alert policy")

	// test env vars
	// create App with env vars
	envVarApp := testutil.AppData()[1]
	envVarApp.Key.Name = "envVarApp"
	envVarApp.EnvVars = map[string]string{
		"env1": "val1",
		"env2": "val2",
	}
	envVarApp.SecretEnvVars = map[string]string{
		"senv1": "secret1",
		"senv2": "secret2",
	}
	_, err = apis.appApi.CreateApp(ctx, envVarApp.Clone())
	require.Nil(t, err)
	found = apis.appApi.Get(envVarApp.GetKey(), &storedApp)
	require.True(t, found)
	require.Equal(t, envVarApp.EnvVars, storedApp.EnvVars)
	require.Equal(t, cloudcommon.RedactSecretVars(envVarApp.SecretEnvVars), storedApp.SecretEnvVars)
	secrets, err := cloudcommon.GetAppSecretVars(ctx, *region, &envVarApp.Key, nodeMgr.VaultConfig)
	require.Nil(t, err)
	require.Equal(t, envVarApp.SecretEnvVars, secrets)

	clone := func(app edgeproto.App) *edgeproto.App {
		// clone skips fields, which we need for update
		copy := app.Clone()
		copy.Fields = app.Fields
		return copy
	}

	// append more env vars
	moreVars := map[string]string{
		"env3": "val3",
		"env4": "var4",
	}
	moreSecretVars := map[string]string{
		"senv3": "secret3",
		"senv4": "secret4",
	}
	envVarUpdate := envVarApp
	envVarUpdate.Fields = []string{
		edgeproto.AppFieldEnvVars,
		edgeproto.AppFieldSecretEnvVars,
		edgeproto.AppFieldUpdateListAction,
	}
	envVarUpdate.UpdateListAction = util.UpdateListActionAdd
	envVarUpdate.EnvVars = moreVars
	envVarUpdate.SecretEnvVars = moreSecretVars
	_, err = apis.appApi.UpdateApp(ctx, clone(envVarUpdate))
	require.Nil(t, err)
	combinedVars := util.AddMaps(envVarApp.EnvVars, moreVars)
	combinedSecrets := util.AddMaps(envVarApp.SecretEnvVars, moreSecretVars)
	require.Equal(t, 4, len(combinedVars))
	require.Equal(t, 4, len(combinedSecrets))
	found = apis.appApi.Get(envVarApp.GetKey(), &storedApp)
	require.True(t, found)
	require.Equal(t, combinedVars, storedApp.EnvVars)
	require.Equal(t, cloudcommon.RedactSecretVars(combinedSecrets), storedApp.SecretEnvVars)
	secrets, err = cloudcommon.GetAppSecretVars(ctx, *region, &envVarApp.Key, nodeMgr.VaultConfig)
	require.Nil(t, err)
	require.Equal(t, combinedSecrets, secrets)

	// now replace, should only be left with env3 and env4
	envVarUpdate.UpdateListAction = util.UpdateListActionReplace
	_, err = apis.appApi.UpdateApp(ctx, clone(envVarUpdate))
	require.Nil(t, err)
	found = apis.appApi.Get(envVarApp.GetKey(), &storedApp)
	require.True(t, found)
	require.Equal(t, moreVars, storedApp.EnvVars)
	require.Equal(t, cloudcommon.RedactSecretVars(moreSecretVars), storedApp.SecretEnvVars)
	secrets, err = cloudcommon.GetAppSecretVars(ctx, *region, &envVarApp.Key, nodeMgr.VaultConfig)
	require.Nil(t, err)
	require.Equal(t, moreSecretVars, secrets)

	// now delete
	deleteVars := map[string]string{
		"env3": "",
	}
	remainingVars := map[string]string{
		"env4": "var4",
	}
	deleteSecretVars := map[string]string{
		"senv3": "",
	}
	remainingSecretVars := map[string]string{
		"senv4": "secret4",
	}
	envVarUpdate.UpdateListAction = util.UpdateListActionRemove
	envVarUpdate.EnvVars = deleteVars
	envVarUpdate.SecretEnvVars = deleteSecretVars
	_, err = apis.appApi.UpdateApp(ctx, clone(envVarUpdate))
	require.Nil(t, err)
	found = apis.appApi.Get(envVarApp.GetKey(), &storedApp)
	require.True(t, found)
	require.Equal(t, remainingVars, storedApp.EnvVars)
	require.Equal(t, cloudcommon.RedactSecretVars(remainingSecretVars), storedApp.SecretEnvVars)
	secrets, err = cloudcommon.GetAppSecretVars(ctx, *region, &envVarApp.Key, nodeMgr.VaultConfig)
	require.Nil(t, err)
	require.Equal(t, remainingSecretVars, secrets)
	// clean up
	_, err = apis.appApi.DeleteApp(ctx, &envVarApp)
	require.Nil(t, err)
	secrets, err = cloudcommon.GetAppSecretVars(ctx, *region, &envVarApp.Key, nodeMgr.VaultConfig)
	require.Nil(t, err)
	require.Equal(t, 0, len(secrets))

	reservedPortsApp := edgeproto.App{
		Key: edgeproto.AppKey{
			Organization: "org",
			Name:         "reservedPortsTest",
			Version:      "1.0",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:8080",
		Deployment:    "kubernetes",
		DefaultFlavor: testutil.FlavorData()[2].Key,
	}

	// test reserved ports
	for p := range edgeproto.ReservedPlatformPorts {
		rpApp := reservedPortsApp
		rpApp.Deployment = cloudcommon.DeploymentTypeKubernetes
		rpApp.AccessPorts = p
		rpApp.DeploymentManifest = ""
		// test create
		_, err = apis.appApi.CreateApp(ctx, &rpApp)
		require.Contains(t, err.Error(), "App cannot use port")
		// test update
		rpApp.AccessPorts = app.AccessPorts
		_, err = apis.appApi.CreateApp(ctx, &rpApp)
		require.Nil(t, err)
		rpApp.AccessPorts = p
		rpApp.Fields = []string{edgeproto.AppFieldAccessPorts}
		_, err = apis.appApi.UpdateApp(ctx, &rpApp)
		require.Contains(t, err.Error(), "App cannot use port")
		// now delete the app
		_, err = apis.appApi.DeleteApp(ctx, &rpApp)
		require.Nil(t, err)
	}

	dummy.Stop()
}

var testInvalidUrlHelmCfg = "http://invalidUrl"
var testValidYmlHelmCfg = `nfs:
  path: /share
  server: [[ .Deployment.ClusterIp ]]
storageClass:
  name: standard
  defaultClass: true
`

func TestValidateAppConfigs(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// valid config
	configs := []*edgeproto.ConfigFile{
		&edgeproto.ConfigFile{
			Kind:   edgeproto.AppConfigHelmYaml,
			Config: testValidYmlHelmCfg,
		},
	}
	err := validateAppConfigsForDeployment(ctx, nil, configs, cloudcommon.DeploymentTypeHelm)
	require.Nil(t, err)

	// invalid url
	configs = []*edgeproto.ConfigFile{
		&edgeproto.ConfigFile{
			Kind:   edgeproto.AppConfigHelmYaml,
			Config: testInvalidUrlHelmCfg,
		},
	}
	err = validateAppConfigsForDeployment(ctx, nil, configs, cloudcommon.DeploymentTypeHelm)
	require.NotNil(t, err)
}

var testVmManifest = `#cloud-config vmManifest`

var testK8SManifest1 = `---
# Source: cornav/templates/gh-configmap.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cornav-graphhopper-cm
data:
  config.yml: "..."
---
# Source: cornav/templates/gh-init-configmap.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cornav-graphhopper-init-cm
data:
  osm.sh: "..."
---
# Source: cornav/templates/gh-pvc.yml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: gh-data-pvc
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: 500Mi
  storageClassName: nfs-client
  volumeMode: Filesystem
---
# Source: cornav/templates/gh-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: cornav-graphhopper
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8989
    protocol: TCP
    name: http
  selector:
    app: cornav-graphhopper
---
# Source: cornav/templates/gh-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cornav-graphhopper
  labels:
    app: cornav-graphhopper
spec:
  selector:
    matchLabels:
      app: cornav-graphhopper
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: cornav-graphhopper
    spec:
      imagePullSecrets:
        - name: regcred
      securityContext:
        runAsUser: 1000
        runAsGroup: 2000
        fsGroup: 2000
      containers:
      - name: cornav-graphhopper
        image: "graphhopper/graphhopper:latest"
        ports:
        - name: http
          containerPort: 8989
          protocol: TCP
        volumeMounts:
        - name: gh-data
          mountPath: /data
        - name: config
          mountPath: /config
        resources:
          limits:
            cpu: 2000m
            memory: 2048Mi
          requests:
            cpu: 1000m
            memory: 1024Mi
      initContainers:
      - name: cornav-init-graphhopper
        image: thomseddon/utils
        env:
        - name: HTTP_PROXY
          value: http://gif-ccs-001.iavgroup.local:3128
        - name: HTTPS_PROXY
          value: http://gif-ccs-001.iavgroup.local:3128
        volumeMounts:
        - mountPath: /data
          name: gh-data
        - mountPath: /init
          name: init-script
        command: ["/init/osm.sh", "-i", "/data/europe_germany_brandenburg.pbf"]
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 100m
            memory: 128Mi
      volumes:
        - name: gh-data
          persistentVolumeClaim:
            claimName: gh-data-pvc
        - name: config
          configMap:
            name: cornav-graphhopper-cm
        - name: init-script
          configMap:
            name: cornav-graphhopper-init-cm
            defaultMode: 0777
`

func testAppResourceConsistency(t *testing.T, ctx context.Context, apis *AllApis) {
	app := testutil.AppData()[0]
	app.Key.Name = "testAppRes"
	app.DefaultFlavor.Name = ""
	app.NodeResources = nil
	app.KubernetesResources = nil
	app.AllowServerless = false
	app.AccessPorts = "tcp:80"

	getKR := func(size string) *edgeproto.KubernetesResources {
		if size == "small" {
			return &edgeproto.KubernetesResources{
				CpuPool: &edgeproto.NodePoolResources{
					TotalVcpus:  *edgeproto.NewUdec64(2, 0),
					TotalMemory: 2048,
					TotalDisk:   2,
					Topology: edgeproto.NodePoolTopology{
						MinNodeVcpus:     2,
						MinNodeMemory:    2048,
						MinNodeDisk:      2,
						MinNumberOfNodes: 1,
					},
				},
			}
		} else if size == "medium" {
			return &edgeproto.KubernetesResources{
				CpuPool: &edgeproto.NodePoolResources{
					TotalVcpus:  *edgeproto.NewUdec64(4, 0),
					TotalMemory: 4096,
					TotalDisk:   4,
					Topology: edgeproto.NodePoolTopology{
						MinNodeVcpus:     4,
						MinNodeMemory:    4096,
						MinNodeDisk:      4,
						MinNumberOfNodes: 1,
					},
				},
			}
		}
		return nil
	}
	getNR := func(size string) *edgeproto.NodeResources {
		if size == "small" {
			return &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
				Disk:  2,
			}
		} else if size == "medium" {
			return &edgeproto.NodeResources{
				Vcpus: 4,
				Ram:   4096,
				Disk:  4,
			}
		}
		return nil
	}

	var tests = []struct {
		desc          string
		modApp        func(*edgeproto.App)
		expectCreated func(*edgeproto.App)
		createErr     string
		modUpdate     func(*edgeproto.App)
		updateErr     string
		expectUpdated func(*edgeproto.App, string)
	}{{
		desc:      "k8s app without resources fails",
		modApp:    func(app *edgeproto.App) {},
		createErr: "missing flavor or Kubernetes resources",
	}, {
		desc: "docker app without resources fails",
		modApp: func(app *edgeproto.App) {
			app.Deployment = cloudcommon.DeploymentTypeDocker
		},
		createErr: "missing flavor or node resources",
	}, {
		desc: "flavor specified converts to KubernetesResources",
		modApp: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.medium"
		},
		expectCreated: func(app *edgeproto.App) {
			require.Empty(t, app.DefaultFlavor)
			require.Empty(t, app.NodeResources)
			require.Equal(t, getKR("medium"), app.KubernetesResources)
		},
	}, {
		desc: "flavor specified converts to NodeResources",
		modApp: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.medium"
			app.Deployment = cloudcommon.DeploymentTypeDocker
		},
		expectCreated: func(app *edgeproto.App) {
			require.Empty(t, app.DefaultFlavor)
			require.Equal(t, getNR("medium"), app.NodeResources)
			require.Empty(t, app.KubernetesResources)
		},
	}, {
		desc: "flavor conflicts with KubernetesResources",
		modApp: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.medium"
			app.KubernetesResources = getKR("small")
		},
		createErr: "cannot specify both flavor and KubernetesResources",
	}, {
		desc: "flavor conflicts with NodeResources",
		modApp: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.medium"
			app.Deployment = cloudcommon.DeploymentTypeDocker
			app.NodeResources = getNR("small")
		},
		createErr: "cannot specify both flavor and NodeResources",
	}, {
		desc: "update Kubernetes Resources ok if no flavor set",
		modApp: func(app *edgeproto.App) {
			app.KubernetesResources = getKR("small")
		},
		expectCreated: func(app *edgeproto.App) {
			require.Equal(t, getKR("small"), app.KubernetesResources)
		},
		modUpdate: func(app *edgeproto.App) {
			app.KubernetesResources = getKR("medium")
			app.Fields = append(app.Fields, edgeproto.AppFieldKubernetesResources)
		},
		expectUpdated: func(app *edgeproto.App, desc string) {
			require.Equal(t, getKR("medium"), app.KubernetesResources, desc)
		},
	}, {
		desc: "update Node Resources ok if no flavor set",
		modApp: func(app *edgeproto.App) {
			app.NodeResources = getNR("small")
			app.Deployment = cloudcommon.DeploymentTypeDocker
		},
		expectCreated: func(app *edgeproto.App) {
			require.Equal(t, getNR("small"), app.NodeResources)
		},
		modUpdate: func(app *edgeproto.App) {
			app.NodeResources = getNR("medium")
			app.Fields = append(app.Fields, edgeproto.AppFieldNodeResources)
		},
		expectUpdated: func(app *edgeproto.App, desc string) {
			require.Equal(t, getNR("medium"), app.NodeResources, desc)
		},
	}, {
		desc: "update flavor cannot override individual kubernetes resources",
		modApp: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.medium"
		},
		modUpdate: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.small"
			app.Fields = append(app.Fields, edgeproto.AppFieldDefaultFlavor)
		},
		updateErr: "cannot specify both flavor and KubernetesResources",
	}, {
		desc: "update flavor cannot override individual node resources",
		modApp: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.medium"
			app.Deployment = cloudcommon.DeploymentTypeDocker
		},
		modUpdate: func(app *edgeproto.App) {
			app.DefaultFlavor.Name = "x1.small"
			app.NodeResources = getNR("medium")
			app.Fields = append(app.Fields, edgeproto.AppFieldDefaultFlavor, edgeproto.AppFieldNodeResources)
		},
		updateErr: "cannot specify both flavor and NodeResources",
	}}

	for _, test := range tests {
		testApp := app
		// modify app for test
		test.modApp(&testApp)
		// create test app
		_, err := apis.appApi.CreateApp(ctx, &testApp)
		if test.createErr != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.createErr, test.desc)
			continue
		}
		require.Nil(t, err, test.desc)
		if test.expectCreated != nil {
			// show created test app
			createdApp := edgeproto.App{}
			found := apis.appApi.cache.Get(&testApp.Key, &createdApp)
			require.True(t, found, test.desc)
			// check created app
			test.expectCreated(&createdApp)
		}
		if test.modUpdate != nil {
			// apply update
			test.modUpdate(&testApp)
			_, err := apis.appApi.UpdateApp(ctx, &testApp)
			if test.updateErr != "" {
				require.NotNil(t, err, test.desc)
				require.Contains(t, err.Error(), test.updateErr, test.desc)
			} else {
				require.Nil(t, err, test.desc)
				// show updated test app
				updatedApp := edgeproto.App{}
				found := apis.appApi.cache.Get(&testApp.Key, &updatedApp)
				require.True(t, found, test.desc)
				test.expectUpdated(&updatedApp, test.desc)
			}
		}
		// cleanup
		_, err = apis.appApi.DeleteApp(ctx, &testApp)
		require.Nil(t, err, test.desc)
	}
}
