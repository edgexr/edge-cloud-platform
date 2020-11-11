package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"testing"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_test"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/stretchr/testify/require"
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

	crm := notify.NewDummyHandler()
	crmServer := &notify.ServerMgr{}
	crm.RegisterServer(crmServer)
	crmServer.Start("crm", *notifyAddrs, nil)
	defer crmServer.Stop()

	// cloudlet must be sent during startup
	crm.CloudletCache.Update(ctx, &shepherd_test.TestCloudlet, 0)
	set := edgeproto.GetDefaultSettings()
	set.ShepherdMetricsCollectionInterval = edgeproto.Duration(time.Second)
	set.ShepherdAlertEvaluationInterval = edgeproto.Duration(3 * time.Second)
	crm.SettingsCache.Update(ctx, set, 0)

	start()
	defer stop()

	crmServer.WaitServerCount(1)

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
	fileContents, err := ioutil.ReadFile(configFile)
	require.Nil(t, err)
	expected := `global:
  evaluation_interval: 3s
rule_files:
- "/tmp/rulefile_*"
scrape_configs:
- job_name: MobiledgeX Monitoring
  scrape_interval: 1s
  file_sd_configs:
  - files:
    - '/tmp/prom_targets.json'
  metric_relabel_configs:
    - source_labels: [envoy_cluster_name]
      target_label: port
      regex: 'backend(.*)'
      replacement: '${1}'
    - regex: 'instance|envoy_cluster_name'
      action: labeldrop
`
	require.Equal(t, expected, string(fileContents))

	// check targets based on appinsts
	fileContents, err = ioutil.ReadFile(*promTargetsFile)
	require.Nil(t, err)
	expected = `[
{
	"targets": ["host.docker.internal:9091"],
	"labels": {
		"app": "App",
		"appver": "",
		"apporg": "",
		"cluster": "testcluster",
		"clusterorg": "",
		"cloudlet": "testcloudlet",
		"cloudletorg": "testoperator",
		"__metrics_path__":"/metrics/App-testcluster--"
	}
}]`
	require.Equal(t, expected, string(fileContents))

	// check alerts based on appinsts and policy

	rulesFile := getAppInstRulesFileName(shepherd_test.TestAppInstKey)
	fileContents, err = ioutil.ReadFile(rulesFile)
	require.Nil(t, err)
	expected = `groups:
- name: autoprov-feature
  rules:
  - alert: AutoProvUndeploy
    expr: envoy_cluster_upstream_cx_active{app="App",appver="",apporg=""} <= 3
    for: 15m
`
	require.Equal(t, expected, string(fileContents))

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
	fileContents, err = ioutil.ReadFile(configFile)
	require.Nil(t, err)
	expected = `global:
  evaluation_interval: 5s
rule_files:
- "/tmp/rulefile_*"
scrape_configs:
- job_name: MobiledgeX Monitoring
  scrape_interval: 1s
  file_sd_configs:
  - files:
    - '/tmp/prom_targets.json'
  metric_relabel_configs:
    - source_labels: [envoy_cluster_name]
      target_label: port
      regex: 'backend(.*)'
      replacement: '${1}'
    - regex: 'instance|envoy_cluster_name'
      action: labeldrop
`
	require.Equal(t, expected, string(fileContents))
	// check rules file (new "for" time)
	fileContents, err = ioutil.ReadFile(rulesFile)
	require.Nil(t, err)
	expected = `groups:
- name: autoprov-feature
  rules:
  - alert: AutoProvUndeploy
    expr: envoy_cluster_upstream_cx_active{app="App",appver="",apporg=""} <= 3
    for: 45s
`
	require.Equal(t, expected, string(fileContents))

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
	fileContents, err = ioutil.ReadFile(rulesFile)
	require.Nil(t, err)
	expected = `groups:
- name: autoprov-feature
  rules:
  - alert: AutoProvUndeploy
    expr: envoy_cluster_upstream_cx_active{app="App",appver="",apporg=""} <= 5
    for: 45s
`
	require.Equal(t, expected, string(fileContents))

	// remove appinst, check for changes
	crm.AppInstCache.Delete(ctx, &shepherd_test.TestAppInst, 0)
	notify.WaitFor(&AppInstCache, 0)
	targetFileWorkers.WaitIdle()
	appInstAlertWorkers.WaitIdle()
	// check targets file (should be empty)
	fileContents, err = ioutil.ReadFile(*promTargetsFile)
	require.Nil(t, err)
	expected = `[]`
	require.Equal(t, expected, string(fileContents))
	// check rules file (should be removed)
	_, err = os.Stat(rulesFile)
	require.True(t, os.IsNotExist(err), "error is %v", err)
	require.Equal(t, 0, len(AppInstByAutoProvPolicy.PolicyKeys))
}
