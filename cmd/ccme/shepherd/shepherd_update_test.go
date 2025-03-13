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

package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	intprocess "github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/shepherd_test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// Test notify and updates
func TestShepherdUpdate(t *testing.T) {
	flag.Parse()
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelInfra | log.DebugLevelMetrics)
	ctx := setupLog()
	defer log.FinishTracer()
	// set up args
	*notifyAddrs = "127.0.0.1:60001"
	ckey, err := json.Marshal(shepherd_test.TestCloudletKey)
	require.Nil(t, err)
	*cloudletKeyStr = string(ckey)
	*platformName = "PLATFORM_TYPE_FAKEINFRA"
	PrometheusClientTimeout = time.Millisecond // no prometheus running

	crm := notify.NewDummyHandler()
	crmServer := &notify.ServerMgr{}
	crm.RegisterServer(crmServer)
	crmServer.Start("crm", *notifyAddrs, nil)
	defer crmServer.Stop()
	// handle access api
	keyServer := node.NewAccessKeyServer(&crm.CloudletCache, "")
	accessKeyGrpcServer := node.AccessKeyGrpcServer{}
	basicUpgradeHandler := node.BasicUpgradeHandler{
		KeyServer: keyServer,
	}
	getPublicCertApi := &cloudcommon.TestPublicCertApi{}
	publicCertManager, err := node.NewPublicCertManager("localhost", "", getPublicCertApi, "", "")
	require.Nil(t, err)
	tlsConfig, err := publicCertManager.GetServerTlsConfig(ctx)
	require.Nil(t, err)
	accessKeyGrpcServer.Start("127.0.0.1:0", keyServer, tlsConfig, func(server *grpc.Server) {
		edgeproto.RegisterCloudletAccessKeyApiServer(server, &basicUpgradeHandler)
	})
	defer accessKeyGrpcServer.Stop()
	// setup access key
	accessKey, err := node.GenerateAccessKey()
	require.Nil(t, err)
	nodeMgr.AccessKeyClient.AccessApiAddr = accessKeyGrpcServer.ApiAddr()
	nodeMgr.AccessKeyClient.AccessKeyFile = "/tmp/acceskey_shepherd_unittest"
	nodeMgr.AccessKeyClient.TestSkipTlsVerify = true
	err = ioutil.WriteFile(nodeMgr.AccessKeyClient.AccessKeyFile, []byte(accessKey.PrivatePEM), 0600)
	require.Nil(t, err)

	// cloudlet must be sent during startup
	cloudlet := shepherd_test.TestCloudlet
	cloudlet.CrmAccessPublicKey = accessKey.PublicPEM
	crm.CloudletCache.Update(ctx, &cloudlet, 0)
	set := edgeproto.GetDefaultSettings()
	set.ShepherdMetricsCollectionInterval = edgeproto.Duration(time.Second)
	set.ShepherdAlertEvaluationInterval = edgeproto.Duration(3 * time.Second)
	// scrape period for coudletPrometheus is a cmd line option
	metricsScrapingInterval = (time.Duration)(set.ShepherdMetricsCollectionInterval)
	crm.SettingsCache.Update(ctx, set, 0)

	start()
	defer stop()

	require.Nil(t, crmServer.WaitServerCount(1))

	// test settings update

	crm.ClusterInstCache.Update(ctx, &shepherd_test.TestClusterInst, 0)
	crm.AutoProvPolicyCache.Update(ctx, &shepherd_test.TestAutoProvPolicy, 0)
	crm.AppCache.Update(ctx, &shepherd_test.TestApp, 0)
	crm.AppInstCache.Update(ctx, &shepherd_test.TestAppInst, 0)

	// wait for changes
	notify.WaitFor(&AppInstCache, 1)
	targetFileWorkers.WaitIdle()
	appInstAlertWorkers.WaitIdle()

	// check global config based on settings
	configFile := intprocess.GetCloudletPrometheusConfigHostFilePath()
	expected := `global:
  evaluation_interval: 3s
rule_files:
- "/var/tmp/rulefile_*"
scrape_configs:
- job_name: EdgeCloud Monitoring
  scrape_interval: 1s
  file_sd_configs:
  - files:
    - '/var/tmp/prom_targets.json'
  metric_relabel_configs:
    - source_labels: [envoy_cluster_name]
      target_label: port
      regex: 'backend(.*)'
      replacement: '${1}'
    - regex: 'instance|envoy_cluster_name'
      action: labeldrop
`
	requireFileContents(t, configFile, expected)

	// check targets based on appinsts
	expected = `[
{
	"targets": ["0.0.0.0:9091"],
	"labels": {
		"appinst": "AppInstTest",
		"appinstorg": "",
		"app": "App",
		"appver": "",
		"apporg": "",
		"cluster": "testcluster",
		"clusterorg": "",
		"cloudlet": "testcloudlet",
		"cloudletorg": "testoperator",
		"cloudletfedorg": "",
		"zone": "testzone",
		"zoneorg": "testoperator",
		"zonefedorg": "",
		"__metrics_path__":"/metrics/AppInstTest-"
	}
}]`
	requireFileContents(t, *promTargetsFile, expected)

	// check alerts based on appinsts and policy

	rulesFile := getAppInstRulesFileName(&shepherd_test.TestAppInst.Key)
	expected = `groups:
- name: autoprov-feature
  rules:
  - alert: AutoProvUndeploy
    expr: envoy_cluster_upstream_cx_active{appinst="AppInstTest",appinstorg=""} <
      3
    for: 15m
`
	requireFileContents(t, rulesFile, expected)

	// update settings, check for changes
	set.ShepherdAlertEvaluationInterval = edgeproto.Duration(5 * time.Second)
	set.AutoDeployIntervalSec = float64(15)
	crm.SettingsCache.Update(ctx, set, 0)
	// wait for changes
	for ii := 0; ii < 50; ii++ {
		if settings.AutoDeployIntervalSec == set.AutoDeployIntervalSec {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	appInstAlertWorkers.WaitIdle()
	// check global config (new eval time)
	expected = `global:
  evaluation_interval: 5s
rule_files:
- "/var/tmp/rulefile_*"
scrape_configs:
- job_name: EdgeCloud Monitoring
  scrape_interval: 1s
  file_sd_configs:
  - files:
    - '/var/tmp/prom_targets.json'
  metric_relabel_configs:
    - source_labels: [envoy_cluster_name]
      target_label: port
      regex: 'backend(.*)'
      replacement: '${1}'
    - regex: 'instance|envoy_cluster_name'
      action: labeldrop
`
	requireFileContents(t, configFile, expected)
	// check rules file (new "for" time)
	expected = `groups:
- name: autoprov-feature
  rules:
  - alert: AutoProvUndeploy
    expr: envoy_cluster_upstream_cx_active{appinst="AppInstTest",appinstorg=""} <
      3
    for: 45s
`
	requireFileContents(t, rulesFile, expected)

	// update policy, check for changes
	policy := shepherd_test.TestAutoProvPolicy
	policy.UndeployClientCount = 5
	crm.AutoProvPolicyCache.Update(ctx, &policy, 0)
	// wait for changes
	for ii := 0; ii < 50; ii++ {
		p := edgeproto.AutoProvPolicy{}
		if found := AutoProvPoliciesCache.Get(&policy.Key, &p); found && p.UndeployClientCount == policy.UndeployClientCount {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	appInstAlertWorkers.WaitIdle()
	// check rules file (new expr)
	expected = `groups:
- name: autoprov-feature
  rules:
  - alert: AutoProvUndeploy
    expr: envoy_cluster_upstream_cx_active{appinst="AppInstTest",appinstorg=""} <
      5
    for: 45s
`
	requireFileContents(t, rulesFile, expected)

	// remove appinst, check for changes
	crm.AppInstCache.Delete(ctx, &shepherd_test.TestAppInst, 0)
	notify.WaitFor(&AppInstCache, 0)
	targetFileWorkers.WaitIdle()
	appInstAlertWorkers.WaitIdle()
	// check targets file (should be empty)
	expected = `[{}]`
	requireFileContents(t, *promTargetsFile, expected)
	// check rules file (should be removed)
	requireFileRemoved(t, rulesFile)
	require.Equal(t, 0, len(AppInstByAutoProvPolicy.PolicyKeys))
}

func requireFileContents(t *testing.T, file string, expected string) {
	timeout := 2 * time.Second
	var contents []byte
	var err error
	for ii := 0; ii < 10; ii++ {
		contents, err = os.ReadFile(file)
		require.Nil(t, err)
		if string(contents) == expected {
			return
		}
		time.Sleep(timeout / time.Duration(10))
	}
	require.Equal(t, expected, string(contents))
}

func requireFileRemoved(t *testing.T, file string) {
	timeout := 2 * time.Second
	var err error
	for ii := 0; ii < 10; ii++ {
		_, err = os.Stat(file)
		if os.IsNotExist(err) {
			return
		}
		time.Sleep(timeout / time.Duration(10))
	}
	require.True(t, os.IsNotExist(err), "require file removed error is %v for file %s", err, file)
}
