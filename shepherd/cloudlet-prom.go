package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	baselog "log"
	"net/http"
	"text/template"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var promTargetTemplate *template.Template

var promTargetT = `
{
	"targets": ["{{.MetricsProxyAddr}}"],
	"labels": {
		"app": "{{.Key.AppKey.Name}}",
		"ver": "{{.Key.AppKey.Version}}",
		"apporg": "{{.Key.AppKey.Organization}}",
		"cluster": "{{.Key.ClusterInstKey.ClusterKey.Name}}",
		"clusterorg": "{{.Key.ClusterInstKey.Organization}}",
		"cloudlet": "{{.Key.ClusterInstKey.CloudletKey.Name}}",
		"cloudletorg": "{{.Key.ClusterInstKey.CloudletKey.Organization}}",
		"__metrics_path__":"{{.EnvoyMetricsPath}}"
	}
}`

var promHealthCheckAlerts = `groups:
- name: StaticRules
  rules:
  - alert: RootLbProxyDown
    expr: up == 0
    for: 1m
  - alert: HealthCheck
    expr: envoy_cluster_health_check_healthy == 0
`

type targetData struct {
	MetricsProxyAddr string
	Key              edgeproto.AppInstKey
	EnvoyMetricsPath string
}

func getAppInstPrometheusTargetString(appInst *edgeproto.AppInst) (string, error) {
	host := *metricsAddr
	switch *platformName {
	case "PLATFORM_TYPE_EDGEBOX":
		fallthrough
	case "PLATFORM_TYPE_FAKEINFRA":
		host = "host.docker.internal:9091"
	}
	target := targetData{
		MetricsProxyAddr: host,
		Key:              appInst.GetKeyVal(),
		EnvoyMetricsPath: "/metrics/" + getProxyKey(&appInst.Key),
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
func writePrometheusTargetsFile() {
	var targets = "["
	AppInstCache.Show(&edgeproto.AppInst{}, func(obj *edgeproto.AppInst) error {
		if targets != "[" {
			targets += ","
		}
		promTargetJson, err := getAppInstPrometheusTargetString(obj)
		if err == nil {
			targets += promTargetJson
		}
		// just skip the targets that we are unable to fill
		return nil
	})
	targets += "]"
	ioutil.WriteFile(*promTargetsFile, []byte(targets), 0644)
}

// Write prometheus rules file and reload rules
func writeCloudletPrometheusAlerts(ctx context.Context, alertsBuf []byte) error {
	// write alerting rules
	err := ioutil.WriteFile(*promAlertsFile, alertsBuf, 0644)
	if err != nil {
		return err
	}
	// need to force prometheus to re-read the rules file
	resp, err := http.Post("http://0.0.0.0:9092/-/reload", "", bytes.NewBuffer([]byte{}))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reload prometheus", "err", err)
		return nil
	}
	resp.Body.Close()
	return nil
}

func targetsList(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>%s</h1>", "List all targets")
	targets := copyMapValues()
	for ii, v := range targets {
		fmt.Fprintf(w, "<h1>Target %d</h1><div>%s</div>", ii, getProxyKey(&v.Key))
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
		if target.ProxyContainer == "nginx" {
			return
		}
		request := fmt.Sprintf("docker exec %s curl -s -S http://127.0.0.1:%d/stats/prometheus", target.ProxyContainer, cloudcommon.ProxyMetricsPort)
		resp, err := target.Client.OutputWithTimeout(request, shepherd_common.ShepherdSshConnectTimeout)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(resp))
	}
}

// Starts Cloudlet Prometheus MetricsProxy thread to serve as a target for metrics
func startPrometheusMetricsProxy(ctx context.Context) error {
	// This works for edgebox and openstack cloudlets for now
	if *platformName == "PLATFORM_TYPE_EDGEBOX" ||
		*platformName == "PLATFORM_TYPE_OPENSTACK" {
		// Init prometheus targets template
		promTargetTemplate = template.Must(template.New("prometheustarget").Parse(promTargetT))
		err := writeCloudletPrometheusAlerts(ctx, []byte(promHealthCheckAlerts))
		if err != nil {
			return fmt.Errorf("Failed to write prometheus rules to %s, err: %s",
				*promAlertsFile, err.Error())
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
	}
	return nil
}
