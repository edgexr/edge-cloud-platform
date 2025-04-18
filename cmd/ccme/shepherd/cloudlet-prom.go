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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	baselog "log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/alerts"
	"github.com/edgexr/edge-cloud-platform/pkg/autorules"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	intprocess "github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/prommgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/shepherd_common"
	"gopkg.in/yaml.v2"
)

const HealthCheckRulesPrefix = "healthcheck"

var CloudletPrometheusAddr = "0.0.0.0:" + intprocess.CloudletPrometheusPort

var promTargetTemplate *template.Template
var targetsLock sync.Mutex
var alertRulesLock sync.Mutex

var PrometheusClientTimeout = 30 * time.Second

var promTargetT = `
{
	"targets": ["{{.MetricsProxyAddr}}"],
	"labels": {
		"` + edgeproto.AppInstKeyTagName + `": "{{.Key.Name}}",
		"` + edgeproto.AppInstKeyTagOrganization + `": "{{.Key.Organization}}",
		"` + edgeproto.AppKeyTagName + `": "{{.AppKey.Name}}",
		"` + edgeproto.AppKeyTagVersion + `": "{{.AppKey.Version}}",
		"` + edgeproto.AppKeyTagOrganization + `": "{{.AppKey.Organization}}",
		"` + edgeproto.ClusterKeyTagName + `": "{{.ClusterKey.Name}}",
		"` + edgeproto.ClusterKeyTagOrganization + `": "{{.ClusterKey.Organization}}",
		"` + edgeproto.CloudletKeyTagName + `": "{{.CloudletKey.Name}}",
		"` + edgeproto.CloudletKeyTagOrganization + `": "{{.CloudletKey.Organization}}",
		"` + edgeproto.CloudletKeyTagFederatedOrganization + `": "{{.CloudletKey.FederatedOrganization}}",
		"` + edgeproto.ZoneKeyTagName + `": "{{.ZoneKey.Name}}",
		"` + edgeproto.ZoneKeyTagOrganization + `": "{{.ZoneKey.Organization}}",
		"` + edgeproto.ZoneKeyTagFederatedOrganization + `": "{{.ZoneKey.FederatedOrganization}}",
		"__metrics_path__":"{{.EnvoyMetricsPath}}"
	}
}`

var promHealthCheckAlerts = `groups:
- name: StaticRules
  rules:
  - alert: ` + cloudcommon.AlertAppInstDown + `
    expr: up == 0
    for: 15s
    labels:
      ` + cloudcommon.AlertHealthCheckStatus + ": %s" + `
      ` + cloudcommon.AlertScopeTypeTag + ": " + cloudcommon.AlertScopeApp + `
    annotations:
      ` + cloudcommon.AlertAnnotationTitle + ": " + cloudcommon.AlertAppInstDown + `
      ` + cloudcommon.AlertAnnotationDescription + ": Root Load Balancer is not responding" + `
  - alert: ` + cloudcommon.AlertAppInstDown + `
    expr: envoy_cluster_health_check_healthy == 0
    labels:
      ` + cloudcommon.AlertHealthCheckStatus + ": %s" + `
      ` + cloudcommon.AlertScopeTypeTag + ": " + cloudcommon.AlertScopeApp + `
    annotations:
      ` + cloudcommon.AlertAnnotationTitle + ": " + cloudcommon.AlertAppInstDown + `
      ` + cloudcommon.AlertAnnotationDescription + ": Application server port is not responding" + `
  - expr: sum by (` + // basically sum over all ports
	strings.Join([]string{edgeproto.AppInstKeyTagName,
		edgeproto.AppInstKeyTagOrganization,
		// non-key fields for App and Cluster are used to populate
		// tags in events for easier searching.
		edgeproto.AppKeyTagName,
		edgeproto.AppKeyTagVersion,
		edgeproto.AppKeyTagOrganization,
		edgeproto.ClusterKeyTagName,
		edgeproto.ClusterKeyTagOrganization,
		edgeproto.CloudletKeyTagName,
		edgeproto.CloudletKeyTagOrganization,
		edgeproto.CloudletKeyTagFederatedOrganization}, ",") +
	`) (envoy_cluster_upstream_cx_active)
    record: envoy_cluster_upstream_cx_active_total
  - expr: avg_over_time(envoy_cluster_upstream_cx_active_total[%ds])
    record: envoy_cluster_upstream_cx_active_total:avg
`

type targetData struct {
	MetricsProxyAddr string
	Key              edgeproto.AppInstKey
	ClusterKey       edgeproto.ClusterKey
	CloudletKey      edgeproto.CloudletKey
	ZoneKey          edgeproto.ZoneKey
	AppKey           edgeproto.AppKey
	EnvoyMetricsPath string
}

func init() {
	promTargetTemplate = template.Must(template.New("prometheustarget").Parse(promTargetT))
}

func updateCloudletPrometheusConfig(ctx context.Context, promScrapeInterval *time.Duration, alertEvalInterval *edgeproto.Duration) error {
	err := intprocess.WriteCloudletPromConfig(ctx, *thanosRecvAddr, &metricsScrapingInterval, (*time.Duration)(&settings.ShepherdAlertEvaluationInterval))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to write cloudlet prometheus config", "err", err)
		return err
	}
	reloadCloudletProm(ctx)
	return nil
}
func getAppInstPrometheusTargetString(proxyScrapePoint *ProxyScrapePoint) (string, error) {
	target := targetData{
		MetricsProxyAddr: *promTargetAddr,
		Key:              proxyScrapePoint.Key,
		AppKey:           proxyScrapePoint.AppKey,
		ClusterKey:       proxyScrapePoint.ClusterKey,
		CloudletKey:      proxyScrapePoint.CloudletKey,
		ZoneKey:          proxyScrapePoint.ZoneKey,
		EnvoyMetricsPath: "/metrics/" + shepherd_common.GetProxyKey(&proxyScrapePoint.Key),
	}
	buf := bytes.Buffer{}
	if err := promTargetTemplate.Execute(&buf, target); err != nil {
		log.DebugLog(log.DebugLevelMetrics, "Failed to create a target", "template", promTargetTemplate,
			"data", target, "error", err)
		return "", err
	}
	return buf.String(), nil
}

// Walk through AppInstances and write out the targets
func writePrometheusTargetsFile(ctx context.Context, key interface{}) {
	targetsLock.Lock()
	defer targetsLock.Unlock()
	var targets = "["
	proxyScrapePoints := copyMapValues()
	for _, val := range proxyScrapePoints {
		if targets != "[" {
			targets += ","
		}
		promTargetJson, err := getAppInstPrometheusTargetString(&val)
		if err == nil {
			targets += promTargetJson
		}
	}
	if len(proxyScrapePoints) == 0 {
		// empty set required
		targets += "{}"
	}
	targets += "]"
	err := ioutil.WriteFile(*promTargetsFile, []byte(targets), 0644)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to write prom targets file", "file", *promTargetsFile, "err", err)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfo, "Wrote prom targets file", "file", *promTargetsFile)
	}
	if runtime.GOOS == "darwin" {
		// probably because of the way docker uses VMs on mac,
		// the file watch doesn't detect changes done to the targets
		// file in the host.
		cmd := exec.Command("docker", "exec", intprocess.PrometheusContainer, "touch", *promTargetsFile)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to touch prom targets file in container to trigger refresh in Prometheus", "out", string(out), "err", err)
		}
		// touch above is sometimes insufficient, so force prometheus
		// to re-read the rules file
		reloadCloudletProm(ctx)
	}
}

// Delete Alert file and reload rules
func deleteCloudletPrometheusAlertFile(ctx context.Context, file string) error {
	// remove alerting rules
	err := os.Remove(file)
	if err != nil {
		return err
	}
	// need to force prometheus to re-read the rules file
	reloadCloudletProm(ctx)
	return nil
}

// Write prometheus rules file and reload rules
func writeCloudletPrometheusAlerts(ctx context.Context, file string, alertsBuf []byte) error {
	alertRulesLock.Lock()
	defer alertRulesLock.Unlock()
	// write alerting rules
	log.SpanLog(ctx, log.DebugLevelInfo, "writing alerts file", "file", file)
	err := ioutil.WriteFile(file, alertsBuf, 0644)
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		// probably because of the way docker uses VMs on mac,
		// the file watch doesn't detect changes done to the targets
		// file in the host.
		cmd := exec.Command("docker", "exec", intprocess.PrometheusContainer, "touch", file)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to touch prom rules file in container to trigger refresh in Prometheus", "out", string(out), "err", err)
		}
	}

	// need to force prometheus to re-read the rules file
	reloadCloudletProm(ctx)
	return nil
}

func reloadCloudletProm(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfo, "reloading prometheus config")
	reqCtx, cancel := context.WithTimeout(ctx, PrometheusClientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", "http://0.0.0.0:9092/-/reload", nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "failed to create http request to reload prometheus", "err", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reload prometheus", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to read prometheus reload response", "code", resp.StatusCode, "err", err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reload prometheus", "code", resp.StatusCode, "err", string(data))
		}
	}
}

func targetsList(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>%s</h1>", "List all targets")
	targets := copyMapValues()
	for ii, v := range targets {
		fmt.Fprintf(w, "<h1>Target %d</h1><div>%s</div>", ii, shepherd_common.GetProxyKey(&v.Key))
	}
}

func metricsProxy(w http.ResponseWriter, r *http.Request) {
	// Sanity check
	if len(r.URL.Path) < len("/metrics/")+1 {
		return
	}
	app := r.URL.Path[len("/metrics/"):]
	if app != "" {
		// Search ProxyMap for the names
		target := getProxyScrapePoint(app)
		if target == nil {
			// no corresponding AppInst proxy, this happens after
			// deletion, because cache gets updated before prometheus
			// gets reloaded without the target. Write back empty
			// data so that prometheus doesn't generate spurious
			// offline alert.
			w.Write([]byte{})
			return
		}
		if target.Client == nil {
			// if client is not initialized trigger health-check failure
			http.Error(w, "Client is not initialized", http.StatusInternalServerError)
			return
		}
		if target.ProxyContainer == "nginx" {
			return
		}
		request := getProxyMetricsRequest(target, "stats/prometheus")
		if cloudletFeatures.IsFake {
			// For e2e testing
			sock := "/tmp/envoy_" + app + ".sock"
			request = fmt.Sprintf("curl -s --unix-socket %s http:/sock/stats/prometheus", sock)
		}
		resp, err := target.Client.OutputWithTimeout(request, shepherd_common.ShepherdSshConnectTimeout)
		if err != nil {
			errStr := fmt.Sprintf("%s[%s]", err, resp)
			http.Error(w, errStr, http.StatusInternalServerError)
			return
		}
		w.Write([]byte(resp))
	}
}

func getAppInstRulesFileName(ai *edgeproto.AppInstKey) string {
	name := k8smgmt.NormalizeName(ai.Name)
	return getPrometheusFileName(name)
}

func getAppInstRulesFileNameCloudletScoped(ai *edgeproto.AppInst) string {
	// this gets the old filename used by the instance if
	// it was renamed during upgrade.
	name := cloudcommon.GetAppInstCloudletScopedName(ai)
	name = k8smgmt.NormalizeName(name)
	return getPrometheusFileName(name)
}

func getPrometheusFileName(name string) string {
	return "/var/tmp/" + intprocess.PrometheusRulesPrefix + name + ".yml"
}

func writeCloudletPrometheusBaseRules(ctx context.Context, settings *edgeproto.Settings) error {
	healthCheckFile := getPrometheusFileName(HealthCheckRulesPrefix)
	serverFailHc, ok := dme.HealthCheck_CamelName[int32(dme.HealthCheck_HEALTH_CHECK_SERVER_FAIL)]
	if !ok {
		return fmt.Errorf("Failed to write prometheus rules - server health check code not found")
	}
	rootLbHc, ok := dme.HealthCheck_CamelName[int32(dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE)]
	if !ok {
		return fmt.Errorf("Failed to write prometheus rules - rootLb health check code not found")
	}
	rules := fmt.Sprintf(promHealthCheckAlerts, rootLbHc, serverFailHc, settings.ClusterAutoScaleAveragingDurationSec)
	err := writeCloudletPrometheusAlerts(ctx, healthCheckFile, []byte(rules))
	if err != nil {
		return fmt.Errorf("Failed to write prometheus rules to %s, err: %s",
			healthCheckFile, err.Error())
	}
	return nil
}

// Starts Cloudlet Prometheus MetricsProxy thread to serve as a target for metrics
func startPrometheusMetricsProxy(ctx context.Context) error {
	// Init prometheus targets and alert templates
	err := writeCloudletPrometheusBaseRules(ctx, &settings)
	if err != nil {
		return err
	}
	// Init http metricsProxy for Prometheus API endpoints
	var nullLogger baselog.Logger
	nullLogger.SetOutput(ioutil.Discard)

	http.HandleFunc("/list", targetsList)
	http.HandleFunc("/metrics/", metricsProxy)
	httpServer := &http.Server{
		Addr:     *metricsAddr,
		ErrorLog: &nullLogger,
	}
	go func() {
		err = httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.FatalLog("Failed to serve metrics", "err", err)
		}
	}()
	return nil
}

func getAutoProvPolicy(ctx context.Context, appInst *edgeproto.AppInst, app *edgeproto.App) (*edgeproto.AutoProvPolicy, bool) {
	for polKey, _ := range app.GetAutoProvPolicys() {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Eval policy", "app", app, "policy", polKey)
		policy := edgeproto.AutoProvPolicy{}
		found := AutoProvPoliciesCache.Get(&polKey, &policy)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find policy", "policy", polKey)
			continue
		}
		// Check if one of the cloudlets in the policy matches ours
		for _, key := range policy.Zones {
			if appInst.ZoneKey.Matches(key) {
				return &policy, true
			}
		}
	}
	// Didn't find any policies that should be enacted on this cloudlet
	return nil, false
}

func writePrometheusAlertRuleForAppInst(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.AppInstKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unexpected failure, key not AppInstKey", "key", key)
		return
	}

	appInst := edgeproto.AppInst{}
	found := AppInstCache.Get(&key, &appInst)
	if !found || appInst.State != edgeproto.TrackedState_READY {
		log.SpanLog(ctx, log.DebugLevelMetrics, "delete rules for AppInst", "AppInstKey", key)
		untrackAppInstByPolicy(key)
		// AppInst is being deleted - delete rules
		fileName := getAppInstRulesFileName(&key)
		if err := deleteCloudletPrometheusAlertFile(ctx, fileName); err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to delete prometheus rules", "file", fileName, "err", err)
		}
		return
	}
	// check cluster name if this is a VM App
	app := edgeproto.App{}
	found = AppCache.Get(&appInst.AppKey, &app)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find app", "app", appInst.AppKey.Name)
		return
	}

	log.SpanLog(ctx, log.DebugLevelMetrics, "write rules for AppInst", "AppInst", key)

	// get any rules for AppInst
	grps := prommgmt.GroupsData{}

	if appInst.Liveness == edgeproto.Liveness_LIVENESS_AUTOPROV {
		// auto-provisioned AppInst, check policy.
		policy, found := getAutoProvPolicy(ctx, &appInst, &app)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "No AutoProvPolicy found", "app", app.Key, "zone", appInst.ZoneKey)
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Apply AutoProvPolicy", "app", app.Key, "zone", appInst.ZoneKey, "policy", policy.Key)
			ruleGrp := autorules.GetAutoUndeployRules(ctx, settings, &appInst.Key, policy)
			if ruleGrp != nil {
				grps.Groups = append(grps.Groups, *ruleGrp)
			}
			trackAppInstByPolicy(appInst.Key, policy.Key)
		}
	}

	// add user-defined alerts for this app Inst as well
	if len(app.AlertPolicies) > 0 {
		userAlerts := []edgeproto.AlertPolicy{}
		for _, alertName := range app.AlertPolicies {
			userAlert := edgeproto.AlertPolicy{
				Key: edgeproto.AlertPolicyKey{
					Name:         alertName,
					Organization: app.Key.Organization,
				},
			}
			found := AlertPolicyCache.Get(&userAlert.Key, &userAlert)
			if !found {
				continue
			}
			userAlerts = append(userAlerts, userAlert)
		}
		userGrp := alerts.GetCloudletAlertRules(ctx, &appInst, userAlerts)
		if userGrp != nil {
			grps.Groups = append(grps.Groups, *userGrp)
		}
	}
	if len(grps.Groups) == 0 {
		// no rules - rulefile should not exist for this
		fileName := getAppInstRulesFileName(&key)
		if err := deleteCloudletPrometheusAlertFile(ctx, fileName); err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to delete prometheus rules", "file", fileName, "err", err)
		}
		return
	}
	byt, err := yaml.Marshal(grps)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to marshal prom rule groups", "AppInst", appInst.Key, "rules", grps, "err", err)
		return
	}

	fileName := getAppInstRulesFileName(&key)
	if appInst.CompatibilityVersion < cloudcommon.AppInstCompatibilityRegionScopeName {
		// for backwards compatibility, delete the old rule file.
		// we can't delete it as part of the delete path, because on the
		// delete path we don't have the full AppInst object.
		oldFile := getAppInstRulesFileNameCloudletScoped(&appInst)
		if oldFile != fileName {
			err = os.Remove(oldFile)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to delete old prom rulefile %s, %s", oldFile, err)
			}
		}
	}
	err = writeCloudletPrometheusAlerts(ctx, fileName, byt)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to write prometheus rules", "file", fileName, "err", err)
	}
}

func trackAppInstByPolicy(appInstKey edgeproto.AppInstKey, policyKey edgeproto.PolicyKey) {
	obj := edgeproto.AppInstLookup{
		Key:       appInstKey,
		PolicyKey: policyKey,
	}
	AppInstByAutoProvPolicy.Updated(&obj)
}

// Unfortunately during removal we may not have the policy used, so we walk
// the data to remove any references to the AppInst. This is ok since we should
// only have a small amount of data just for this Cloudlet.
func untrackAppInstByPolicy(appInstKey edgeproto.AppInstKey) {
	s := &AppInstByAutoProvPolicy
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for policyKey, insts := range s.PolicyKeys {
		delete(insts, appInstKey)
		if len(insts) == 0 {
			delete(s.PolicyKeys, policyKey)
		}
	}
}
