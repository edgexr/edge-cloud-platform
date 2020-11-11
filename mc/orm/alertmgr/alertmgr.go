package alertmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"

	//"github.com/prometheus/alertmanager/api/v2/models"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	models "github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/models"

	//	alertmanager_config "github.com/prometheus/alertmanager/config"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	alertmanager_config "github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/config"
)

// Default alertmanager configuration
var defaultConfigTemplate *template.Template

// AlertMgrServer does two things - it periodically updates AlertManager about the
// current alerts on the system, and also handles configuration for the alert receivers
// i.e. backend handlers for the MC apis.
// NOTE: it does not perform any RBAC control here - this is done in ORM handlers
type AlertMgrServer struct {
	AlertMrgAddr          string
	AlertResolutionTimout time.Duration
	AlertRefreshInterval  time.Duration
	AlertCache            *edgeproto.AlertCache
	TlsConfig             *tls.Config
	waitGrp               sync.WaitGroup
	stop                  chan struct{}
}

// TODO - use version to track where this alert came from
func getAgentName() string {
	return "MasterControllerV1"
}

// resolveTimeout should be at least 3x of alert refresh rate
func getAlertRefreshRate(resolveTimeout time.Duration) time.Duration {
	if alertRefreshInterval < resolveTimeout/3 {
		return alertRefreshInterval
	}
	return resolveTimeout / 3
}

func NewAlertMgrServer(alertMgrAddr string, tlsConfig *tls.Config,
	alertCache *edgeproto.AlertCache, resolveTimeout time.Duration) (*AlertMgrServer, error) {
	var err error
	server := AlertMgrServer{
		AlertMrgAddr:          alertMgrAddr,
		AlertCache:            alertCache,
		AlertResolutionTimout: resolveTimeout,
		TlsConfig:             tlsConfig,
	}
	span := log.StartSpan(log.DebugLevelApi|log.DebugLevelInfo, "AlertMgrServer")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	server.AlertRefreshInterval = getAlertRefreshRate(resolveTimeout)
	// We might need to wait for alertmanager to be up first
	for ii := 0; ii < 10; ii++ {
		_, err = alertMgrApi(ctx, server.AlertMrgAddr, "GET", "", "", nil, server.TlsConfig)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to connect to alertmanager", "err", err)
		return nil, err
	}
	return &server, nil
}

// Update callback for a new alert - should send to alertmanager right away
func (s *AlertMgrServer) UpdateAlert(ctx context.Context, old *edgeproto.Alert, new *edgeproto.Alert) {
	s.AddAlerts(ctx, new)
}

func (s *AlertMgrServer) Start() {
	s.stop = make(chan struct{})
	s.waitGrp.Add(1)
	go s.runServer()
}

func (s *AlertMgrServer) runServer() {
	done := false
	for !done {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(s.AlertRefreshInterval):
			span := log.StartSpan(log.DebugLevelInfo, "alert-mgr")
			ctx := log.ContextWithSpan(context.Background(), span)
			log.SpanLog(ctx, log.DebugLevelInfo, "Sending Alerts to AlertMgr", "AlertMrgAddr",
				s.AlertMrgAddr)
			curAlerts := []*edgeproto.Alert{}
			s.AlertCache.Show(&edgeproto.Alert{}, func(obj *edgeproto.Alert) error {
				curAlerts = append(curAlerts, obj)
				return nil
			})
			// Send out alerts if any alerts need updating
			if len(curAlerts) > 0 {
				err := s.AddAlerts(ctx, curAlerts...)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfo, "Error sending Alerts to AlertMgr", "AlertMrgAddr",
						s.AlertMrgAddr, "err", err)
				}
			}
			span.Finish()
		case <-s.stop:
			done = true
		}
	}
	s.waitGrp.Done()
}

func (s *AlertMgrServer) Stop() {
	close(s.stop)
	s.waitGrp.Wait()
}

func (s *AlertMgrServer) alertsToOpenAPIAlerts(alerts []*edgeproto.Alert) models.PostableAlerts {
	openAPIAlerts := models.PostableAlerts{}
	for _, a := range alerts {
		start := strfmt.DateTime(time.Unix(a.ActiveAt.Seconds, int64(a.ActiveAt.Nanos)))
		// Set endsAt to now + s.AlertResolutionTimout
		end := strfmt.DateTime(time.Now().Add(s.AlertResolutionTimout))
		labels := make(map[string]string)
		for k, v := range a.Labels {
			// Convert appInst status to a human-understandable format
			if k == cloudcommon.AlertHealthCheckStatus {
				if tmp, err := strconv.ParseInt(v, 10, 32); err == nil {
					if _, ok := edgeproto.HealthCheck_CamelName[int32(tmp)]; ok {
						v = edgeproto.HealthCheck_CamelName[int32(tmp)]
					}
				}
			}
			labels[k] = v
		}
		openAPIAlerts = append(openAPIAlerts, &models.PostableAlert{
			Annotations: copyMap(a.Annotations),
			StartsAt:    start,
			EndsAt:      end,
			Alert: models.Alert{
				Labels: copyMap(labels),
			},
		})
	}
	return openAPIAlerts
}

func copyMap(labels map[string]string) map[string]string {
	apiLabelSet := models.LabelSet{}
	for k, v := range labels {
		apiLabelSet[k] = v
	}
	return apiLabelSet
}

func alertManagerAlertsToEdgeprotoAlerts(openAPIAlerts models.GettableAlerts) []edgeproto.Alert {
	alerts := []edgeproto.Alert{}
	for _, openAPIAlert := range openAPIAlerts {
		alert := edgeproto.Alert{}
		if openAPIAlert.StartsAt != nil {
			alert.ActiveAt = dme.Timestamp{
				Seconds: time.Time(*openAPIAlert.StartsAt).Unix(),
				Nanos:   int32(time.Time(*openAPIAlert.StartsAt).UnixNano()),
			}
		}
		alert.Labels = copyMap(openAPIAlert.Labels)
		alert.Annotations = copyMap(openAPIAlert.Annotations)
		alerts = append(alerts, alert)
	}
	return alerts
}

// Show all alerts in the alertmgr
func (s *AlertMgrServer) ShowAlerts(ctx context.Context, filter *edgeproto.Alert) ([]edgeproto.Alert, error) {
	data, err := alertMgrApi(ctx, s.AlertMrgAddr, "GET", AlertApi, "", nil, s.TlsConfig)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to GET Alerts", "err", err, "filter", filter)
		return nil, err
	}
	openAPIAlerts := models.GettableAlerts{}
	err = json.Unmarshal(data, &openAPIAlerts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to unmarshal Alerts", "err", err, "data", data)
		return nil, err
	}
	alerts := alertManagerAlertsToEdgeprotoAlerts(openAPIAlerts)
	return alerts, nil
}

// Marshal edgeproto.Alert into json payload suitabe for alertmanager api
func (s *AlertMgrServer) AddAlerts(ctx context.Context, alerts ...*edgeproto.Alert) error {
	openApiAlerts := s.alertsToOpenAPIAlerts(alerts)
	data, err := json.Marshal(openApiAlerts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to marshal alerts", "err", err, "alerts", alerts)
		return err
	}
	res, err := alertMgrApi(ctx, s.AlertMrgAddr, "POST", AlertApi, "", data, s.TlsConfig)
	log.SpanLog(ctx, log.DebugLevelInfo, "marshal alerts", "alerts", string(data), "err", err, "res", res)
	return err
}

func getAlertmgrReceiverName(receiver *ormapi.AlertReceiver) string {
	return receiver.Name + "-" + receiver.User + "-" + receiver.Severity + "-" + receiver.Type
}

func getRouteMatchLabelsFromAlertReceiver(in *ormapi.AlertReceiver) map[string]string {
	labels := map[string]string{}
	if in.Cloudlet.Organization != "" {
		// add labels for the cloudlet
		labels[edgeproto.CloudletKeyTagOrganization] = in.Cloudlet.Organization
		if in.Cloudlet.Name != "" {
			labels[edgeproto.CloudletKeyTagName] = in.Cloudlet.Name
		}
	}
	if in.AppInst.AppKey.Organization != "" {
		// add labels for app instance
		labels[edgeproto.AppKeyTagOrganization] = in.AppInst.AppKey.Organization
		if in.AppInst.AppKey.Name != "" {
			labels[edgeproto.AppKeyTagName] = in.AppInst.AppKey.Name
		}
		if in.AppInst.AppKey.Version != "" {
			labels[edgeproto.AppKeyTagVersion] = in.AppInst.AppKey.Version
		}
		if in.AppInst.ClusterInstKey.CloudletKey.Name != "" {
			labels[edgeproto.CloudletKeyTagName] = in.AppInst.ClusterInstKey.CloudletKey.Name
		}
		if in.AppInst.ClusterInstKey.CloudletKey.Organization != "" {
			labels[edgeproto.CloudletKeyTagOrganization] = in.AppInst.ClusterInstKey.CloudletKey.Organization
		}
		if in.AppInst.ClusterInstKey.ClusterKey.Name != "" {
			labels[edgeproto.ClusterKeyTagName] = in.AppInst.ClusterInstKey.ClusterKey.Name
		}
		if in.AppInst.ClusterInstKey.Organization != "" {
			labels[edgeproto.ClusterInstKeyTagOrganization] = in.AppInst.ClusterInstKey.Organization
		}
	}
	return labels
}

// Receiver includes a route and a receiver which will receive the alert
// we create a route on the org tags for a given appInstance
func (s *AlertMgrServer) CreateReceiver(ctx context.Context, receiver *ormapi.AlertReceiver) error {
	var rec alertmanager_config.Receiver

	// sanity - certain characters should not be part of the receiver name
	if strings.ContainsAny(receiver.Name, "-:") {
		return fmt.Errorf("Receiver name cannot contain dashes(\"-\"), or colons(\":\")")
	}
	// get a labelset from the receiver
	routeMatchLabels := getRouteMatchLabelsFromAlertReceiver(receiver)

	// We create one entry per receiver, to make it simpler
	receiverName := getAlertmgrReceiverName(receiver)

	notifierCfg := alertmanager_config.NotifierConfig{
		VSendResolved: true,
	}
	// add a new receiver
	switch receiver.Type {
	case AlertReceiverTypeEmail:
		emailCfg := alertmanager_config.EmailConfig{
			NotifierConfig: notifierCfg,
			To:             receiver.Email,
			HTML:           alertmanagerConfigEmailHtmlTemplate,
			Headers: map[string]string{
				"Subject": alertmanagerConfigEmailSubjectTemplate,
			},
			Text: alertmanagerConfigEmailTextTemplate,
		}
		rec = alertmanager_config.Receiver{
			// to make the name unique - construct it with all the fields and username
			Name:         receiverName,
			EmailConfigs: []*alertmanager_config.EmailConfig{&emailCfg},
		}
	case AlertReceiverTypeSlack:
		slackUrl, err := url.Parse(receiver.SlackWebhook)
		if err != nil || !strings.HasPrefix(slackUrl.Scheme, "http") {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse slack URL",
				"url", receiver.SlackWebhook)
			return fmt.Errorf("Invalid Slack api URL")
		}
		slackCfg := alertmanager_config.SlackConfig{
			NotifierConfig: notifierCfg,
			Channel:        receiver.SlackChannel,
			APIURL: &alertmanager_config.URL{
				URL: slackUrl,
			},
			Title:     alertmanagerConfigSlackTitle,
			Text:      alertmanagerConfigSlackText,
			TitleLink: alertmanagerConfigSlackTitleLink,
			Fallback:  alertmanagerConfigSlackFallback,
			IconURL:   alertmanagerConfigSlackIcon,
		}
		rec = alertmanager_config.Receiver{
			// to make the name unique - construct it with all the fields and username
			Name:         receiverName,
			SlackConfigs: []*alertmanager_config.SlackConfig{&slackCfg},
		}
	default:
		log.SpanLog(ctx, log.DebugLevelInfo, "Unsupported receiver type", "type", receiver.Type,
			"receiver", receiver)
		return fmt.Errorf("Invalid receiver type - %s", receiver.Type)
	}
	// add route - match labels passed in
	route := alertmanager_config.Route{
		Receiver: receiverName,
		Match:    routeMatchLabels,
		Continue: true,
	}
	sidecarRec := SidecarReceiverConfig{
		Receiver: rec,
		Route:    route,
	}

	// Send request to sidecar service
	data, err := json.Marshal(sidecarRec)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to get marshal sidecar Receiver Config info", "err", err, "cfg", sidecarRec)
		return err
	}
	res, err := alertMgrApi(ctx, s.AlertMrgAddr, "POST", mobiledgeXReceiverApi, "", data, s.TlsConfig)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to create alertmanager receiver", "err", err, "res", res)
		return err
	}
	return nil
}

func (s *AlertMgrServer) DeleteReceiver(ctx context.Context, receiver *ormapi.AlertReceiver) error {
	// sanity - certain characters should not be part of the receiver name
	if strings.ContainsAny(receiver.Name, "-:") {
		return fmt.Errorf("Receiver name cannot contain dashes(\"-\"), or colons(\":\")")
	}

	// We create one entry per receiver, to make it simpler
	receiverName := getAlertmgrReceiverName(receiver)
	res, err := alertMgrApi(ctx, s.AlertMrgAddr, "DELETE", mobiledgeXReceiverApi+"/"+receiverName, "", nil, s.TlsConfig)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to delete alertmanager receiver", "err", err, "res", res)
		return err
	}
	return nil
}

func getAlertReceiverFromName(name string) (*ormapi.AlertReceiver, error) {
	receiver := ormapi.AlertReceiver{}
	vals := strings.Split(name, "-")
	if len(vals) != 4 {
		return nil, fmt.Errorf("Unable to parse receiver name: %s", name)
	}
	receiver.Name = vals[0]
	receiver.User = vals[1]
	receiver.Severity = vals[2]
	receiver.Type = vals[3]
	return &receiver, nil
}

func alertReceiverMatchesFilter(receiver *ormapi.AlertReceiver, filter *ormapi.AlertReceiver) bool {
	if filter != nil {
		if filter.Name != "" && filter.Name != receiver.Name ||
			filter.Email != "" && filter.Email != receiver.Email ||
			filter.Severity != "" && filter.Severity != receiver.Severity ||
			filter.Type != "" && filter.Type != receiver.Type ||
			filter.User != "" && filter.User != receiver.User ||
			filter.SlackChannel != "" && filter.SlackChannel != receiver.SlackChannel ||
			!receiver.Cloudlet.Matches(&filter.Cloudlet, edgeproto.MatchFilter()) ||
			!receiver.AppInst.Matches(&filter.AppInst, edgeproto.MatchFilter()) {
			return false
		}
	}
	return true
}
func (s *AlertMgrServer) ShowReceivers(ctx context.Context, filter *ormapi.AlertReceiver) ([]ormapi.AlertReceiver, error) {
	alertReceivers := []ormapi.AlertReceiver{}
	apiUrl := mobiledgeXReceiversApi
	if filter != nil && filter.Name != "" {
		// Add Filter with a name
		apiUrl = mobiledgeXReceiverApi + "/" + filter.Name
	}
	data, err := alertMgrApi(ctx, s.AlertMrgAddr, "GET", apiUrl, "", nil, s.TlsConfig)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to GET Alert Receivers", "err", err)
		return nil, err
	}
	sidecarReceiverConfigs := []SidecarReceiverConfig{}
	err = json.Unmarshal(data, &sidecarReceiverConfigs)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to unmarshal Alert receivers", "err", err, "data", data)
		return nil, err
	}

	// walk config receivers and create an ormReceiver from it
	for _, rec := range sidecarReceiverConfigs {
		// skip default receiver
		if rec.Receiver.Name == "default" {
			continue
		}
		receiver, err := getAlertReceiverFromName(rec.Receiver.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Unable to parse receiver", "err", err, "receiver", rec.Receiver)
			continue
		}
		switch receiver.Type {
		case AlertReceiverTypeEmail:
			receiver.Email = rec.Receiver.EmailConfigs[0].To
		case AlertReceiverTypeSlack:
			receiver.SlackChannel = rec.Receiver.SlackConfigs[0].Channel
			receiver.SlackWebhook = AlertMgrSlackWebhookToken
		default:
			log.SpanLog(ctx, log.DebugLevelApi, "Unknown receiver type", "type", receiver.Type)
		}
		route := rec.Route
		// Based on the labels it's either cloudlet, or appInst
		if apporg, ok := route.Match[edgeproto.AppKeyTagOrganization]; ok {
			// appinst
			receiver.AppInst.AppKey.Organization = apporg
			if appname, ok := route.Match[edgeproto.AppKeyTagName]; ok {
				receiver.AppInst.AppKey.Name = appname
			}
			if ver, ok := route.Match[edgeproto.AppKeyTagVersion]; ok {
				receiver.AppInst.AppKey.Version = ver
			}
			if cluster, ok := route.Match[edgeproto.ClusterKeyTagName]; ok {
				receiver.AppInst.ClusterInstKey.ClusterKey.Name = cluster
			}
			if clusterorg, ok := route.Match[edgeproto.ClusterInstKeyTagOrganization]; ok {
				receiver.AppInst.ClusterInstKey.Organization = clusterorg
			}
			if cloudlet, ok := route.Match[edgeproto.CloudletKeyTagName]; ok {
				receiver.AppInst.ClusterInstKey.CloudletKey.Name = cloudlet
			}
			if cloudletorg, ok := route.Match[edgeproto.CloudletKeyTagOrganization]; ok {
				receiver.AppInst.ClusterInstKey.CloudletKey.Organization = cloudletorg
			}
		} else if cloudletorg, ok := route.Match[edgeproto.CloudletKeyTagOrganization]; ok {
			// cloudlet
			receiver.Cloudlet.Organization = cloudletorg
			if cloudlet, ok := route.Match[edgeproto.CloudletKeyTagName]; ok {
				receiver.Cloudlet.Name = cloudlet
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Unexpected receiver map data for route", "route", route)
			continue
		}
		// Check against a filter
		if alertReceiverMatchesFilter(receiver, filter) {
			alertReceivers = append(alertReceivers, *receiver)
		}
	}
	return alertReceivers, nil
}

// Common function to send an api call to alertmanager
func alertMgrApi(ctx context.Context, addr, method, api, options string, payload []byte, tlsConfig *tls.Config) ([]byte, error) {
	var client *http.Client

	apiUrl := addr + api
	if options != "" {
		apiUrl += "?" + options
	}
	urlObj, err := url.Parse(apiUrl)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse url", "err", err, "url", apiUrl)
		return nil, err
	}
	if urlObj.Scheme == "http" {
		client = http.DefaultClient
	} else if urlObj.Scheme == "https" {
		if tlsConfig == nil {
			client = http.DefaultClient
		} else {
			log.SpanLog(ctx, log.DebugLevelInfo, "Tls client config", "addr", addr, "tls certs", tlsConfig.Certificates)
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unsupported schema", "err", err, "url", apiUrl)
		return nil, err
	}
	req, err := http.NewRequest(method, apiUrl, bytes.NewReader(payload))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to create a new alerts request", "err", err, "url", apiUrl)
		return nil, err
	}
	// Make sure that the connection is closed after we are done with it.
	req.Close = true
	req.Header.Set("User-Agent", getAgentName())
	if method == http.MethodPost || method == http.MethodDelete {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to send request to the alertmanager", "err", err,
			"method", req.Method, "url", req.URL, "payload", payload)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	// HTTP status 2xx is ok
	if resp.StatusCode/100 != 2 {
		var errorStr string
		if err == nil {
			respErr := strings.TrimSuffix(string(body), "\n")
			errorStr = fmt.Sprintf("bad response status %s[%s]", resp.Status, respErr)
		} else {
			errorStr = fmt.Sprintf("bad response status %s", resp.Status)
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "Alertmanager responded with an error", "method", req.Method,
			"url", req.URL, "payload", payload, "response code", resp.Status,
			"response length", resp.ContentLength, "body", string(body))
		return nil, fmt.Errorf("%s", errorStr)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to read response body", "err", err,
			"method", req.Method, "url", req.URL, "payload", payload,
			"response code", resp.Status, "response length", resp.ContentLength)
		return nil, err
	}
	return body, nil
}
