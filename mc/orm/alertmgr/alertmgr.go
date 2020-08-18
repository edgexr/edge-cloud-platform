package alertmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"

	//"github.com/prometheus/alertmanager/api/v2/models"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	models "github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/models"

	//	alertmanager_config "github.com/prometheus/alertmanager/config"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	alertmanager_config "github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/config"
)

var alertRefreshInterval = 30 * time.Second

// Default alertmanager configuration
var defaultConfigTemplate *template.Template

// Notes on the default values:
//   resolve_timeout - since we refresh  this every minute, 3xmins should be sufficient
//   group_wait - since we are not grouping alerts right now, 1 sec for instant alert send
//   group_interval - since we are grouping this setting doesn't do anything, but we might use it in the future
//   repeat_interval - re-send every 2hrs until resolved
const DefaultAlertmanagerConfigT = `global:
  resolve_timeout: {{.ResolveTimeout}}
  smtp_from: "{{.Email}}"
  smtp_smarthost: {{.Smtp}}:{{.Port}}
  smtp_auth_username: "{{.User}}"
  smtp_auth_identity: "{{.User}}"
  smtp_auth_password: "{{.Token}}"
  {{if .Tls}}smtp_require_tls: {{.Tls}}{{end}}
route:
  group_wait: 1s
  group_interval: 1s
  repeat_interval: 2h
  receiver: default
receivers:
- name: default
`

// This is moslty taken from https://github.com/prometheus/alertmanager/blob/master/template/default.tmpl with minor modifications
// TODO - need to write this in a more MobiledgeXy type of an email
var alertmanagerConfigEmailHtmlTemplate = `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!--
Style and HTML derived from https://github.com/mailgun/transactional-email-templates


The MIT License (MIT)

Copyright (c) 2014 Mailgun

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-->
<html xmlns="http://www.w3.org/1999/xhtml" xmlns="http://www.w3.org/1999/xhtml" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
<head style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
<meta name="viewport" content="width=device-width" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
<title style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">` + alertmanagerCOnfigEmailSubjectTemplate + `</title>

</head>

<body itemscope="" itemtype="http://schema.org/EmailMessage" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: none; height: 100%; line-height: 1.6em; width: 100% !important; background-color: #f6f6f6; margin: 0; padding: 0;" bgcolor="#f6f6f6">

<table style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; width: 100%; background-color: #f6f6f6; margin: 0;" bgcolor="#f6f6f6">
  <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
    <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0;" valign="top"></td>
    <td width="600" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; display: block !important; max-width: 600px !important; clear: both !important; width: 100% !important; margin: 0 auto; padding: 0;" valign="top">
      <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; max-width: 600px; display: block; margin: 0 auto; padding: 0;">
        <table width="100%" cellpadding="0" cellspacing="0" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; border-radius: 3px; background-color: #fff; margin: 0; border: 1px solid #e9e9e9;" bgcolor="#fff">
          <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
            <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box- sizing: border-box; font-size: 16px; vertical-align: top; color: #fff; font-weight: 500; text-align: center; border-radius: 3px 3px 0 0; background-color: #292C33; margin: 0; padding: 20px;" align="center" bgcolor="#292C33" valign="top">
              {{ .Alerts | len }} alert{{ if gt (len .Alerts) 1 }}s{{ end }} for {{ range .GroupLabels.SortedPairs }}
                {{ .Name }}={{ .Value }}
              {{ end }}
            </td>
          </tr>
          <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
            <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 10px;" valign="top">
              <table width="100%" cellpadding="0" cellspacing="0" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                  <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <a href="https://console.mobiledgex.net" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; color: #FFF; text-decoration: none; line-height: 2em; font-weight: bold; text-align: center; cursor: pointer; display: inline-block; border-radius: 5px; text-transform: capitalize; background-color: #74AA19; margin: 0; border-color: #74AA19; border-style: solid; border-width: 10px 20px;">View on MobiledgeX Console </a>
                  </td>
                </tr>
                {{ if gt (len .Alerts.Firing) 0 }}
                <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                  <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <strong style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">[{{ .Alerts.Firing | len }}] Firing</strong>
                  </td>
                </tr>
                {{ end }}
                {{ range .Alerts.Firing }}
                <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                  <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <strong style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">Labels</strong><br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
                    {{ range .Labels.SortedPairs }}{{ .Name }} = {{ .Value }}<br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />{{ end }}
                    {{ if gt (len .Annotations) 0 }}<strong style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">Annotations</strong><br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />{{ end }}
                    {{ range .Annotations.SortedPairs }}{{ .Name }} = {{ .Value }}<br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />{{ end }}
                  </td>
                </tr>
                {{ end }}

                {{ if gt (len .Alerts.Resolved) 0 }}
                  {{ if gt (len .Alerts.Firing) 0 }}
                <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                  <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
                    <hr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
                    <br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
                  </td>
                </tr>
                  {{ end }}
                <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                  <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <strong style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">[{{ .Alerts.Resolved | len }}] Resolved</strong>
                  </td>
                </tr>
                {{ end }}
                {{ range .Alerts.Resolved }}
                <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
                  <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <strong style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">Labels</strong><br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
                    {{ range .Labels.SortedPairs }}{{ .Name }} = {{ .Value }}<br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />{{ end }}
                    {{ if gt (len .Annotations) 0 }}<strong style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">Annotations</strong><br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />{{ end }}
                    {{ range .Annotations.SortedPairs }}{{ .Name }} = {{ .Value }}<br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />{{ end }}
                    <a href="{{ .GeneratorURL }}" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; color: #348eda; text-decoration: underline; margin: 0;">Source</a><br style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" />
                  </td>
                </tr>
                {{ end }}
              </table>
            </td>
          </tr>
        </table>

        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; width: 100%; clear: both; color: #999; margin: 0; padding: 20px;">
          <table width="100%" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
            <tr style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
              <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 12px; vertical-align: top; text-align: center; color: #999; margin: 0; padding: 0 0 20px;" align="center" valign="top"><a href="https://console.mobiledgex.net/" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 12px; color: #999; text-decoration: underline; margin: 0;">Sent by MobiledX Monitoring</a></td>
            </tr>
          </table>
        </div></div>
    </td>
    <td style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0;" valign="top"></td>
  </tr>
</table>

</body>
</html>
`

// NOTE - below only works for an appInst alert, not a cloudlet alert.
var alertmanagerCOnfigEmailSubjectTemplate = `[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{.CommonLabels.alertname}} Application: {{.CommonLabels.` + edgeproto.AppKeyTagName + `}} Version: {{.CommonLabels.` + edgeproto.AppKeyTagVersion + `}}`

var alertmanagerConfigEmailTextTemplate = `
MobiledX Monitoring System: {{ .Alerts | len }} alert{{ if gt (len .Alerts) 1 }}s{{ end }} for {{ range .GroupLabels.SortedPairs }}
  {{ .Name }}={{ .Value }}
{{ end }}
{{ if gt (len .Alerts.Firing) 0 }}
  [{{ .Alerts.Firing | len }}] Firing
{{ end }}
{{ if gt (len .Alerts.Resolved) 0 }}
  [{{ .Alerts.Resolved | len }}] Resolved
{{ end }}
`

const (
	AlertReceiverTypeEmail = "email"
	AlertReceiverTypeSlack = "slack"
	AlertSeverityError     = "error"
	AlertSeverityWarn      = "warning"
	AlertSeverityInfo      = "info"
)

// We will use this to read and write alertmanager config file
// Use AlertManagerGlobalConfig.String() to get the new file
// Use alertmanager_config.LoadFile(filename string) func to create AlertManagerConfig
// Use alertmanager_config.Load(s string) to test with example yamls
var AlertManagerConfig *alertmanager_config.Config
var configLock sync.RWMutex

const (
	AlertApi        string = "api/v2/alerts"
	ReceiverApi     string = "api/v2/receivers"
	SilenceApi      string = "api/v2/silences"
	ReloadConfigApi string = "-/reload"
)

// AlertMgrServer does two things - it periodically updates AlertManager about the
// current alerts on the system, and also handles configuration for the alert receivers
// i.e. backend handlers for the MC apis.
// NOTE: it does not perform any RBAC control here - this is done in ORM handlers
type AlertMgrServer struct {
	AlertMrgAddr            string
	McAlertmanagerAgentName string
	AlertMgrConfigPath      string
	AlertResolutionTimout   time.Duration
	AlertCache              *edgeproto.AlertCache
	vaultConfig             *vault.Config
	localVault              bool
	waitGrp                 sync.WaitGroup
	stop                    chan struct{}
}

type smtpInfo struct {
	Email          string `json:"email"`
	User           string `json:"user,omitempty"`
	Token          string `json:"token,omitempty"`
	Smtp           string `json:"smtp"`
	Port           string `json:"port"`
	Tls            string `json:"tls,omitempty"`
	ResolveTimeout string `json:"-"`
}

// TODO - use version to track where this alert came from
func setAgentName() string {
	return "MasterControllerV1"
}

func NewAlertMgrServer(alertMgrAddr string, configPath string, vaultConfig *vault.Config, localVault bool, alertCache *edgeproto.AlertCache, resolveTimeout time.Duration) (*AlertMgrServer, error) {
	var err error
	server := AlertMgrServer{
		AlertMrgAddr:            alertMgrAddr,
		AlertCache:              alertCache,
		McAlertmanagerAgentName: setAgentName(),
		AlertMgrConfigPath:      configPath,
		vaultConfig:             vaultConfig,
		localVault:              localVault,
		AlertResolutionTimout:   resolveTimeout,
	}
	span := log.StartSpan(log.DebugLevelApi|log.DebugLevelInfo, "AlertMgrServer")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	// We might need to wait for alertmanager to be up first
	for ii := 0; ii < 10; ii++ {
		_, err = server.alertMgrApi(ctx, "GET", "", "", nil)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to connect to alertmanager", "err", err)
		return nil, err
	}
	if err := server.readConfigFile(ctx); err != nil {
		return nil, err
	}
	return &server, nil
}

func (s *AlertMgrServer) getAlertmanagertSmtpConfig(ctx context.Context) (*smtpInfo, error) {
	if s.localVault {
		log.SpanLog(ctx, log.DebugLevelApi, "Using dummy smtp credentials")
		return &testSmtpInfo, nil
	}
	alertMgrAcct := smtpInfo{}
	err := vault.GetData(s.vaultConfig,
		"/secret/data/accounts/alertmanagersmtp", 0, &alertMgrAcct)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to get data from vault", "err", err)
		return nil, err
	}
	return &alertMgrAcct, nil
}

// Load default configuration into Alertmanager
// Note configLock should be held prior to calling this
func (s *AlertMgrServer) loadDefaultConfigFileLocked(ctx context.Context) error {
	smtpInfo, err := s.getAlertmanagertSmtpConfig(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to get Smtp from vault", "err", err, "cfg", s.vaultConfig)
		return err
	}
	var secs = int(s.AlertResolutionTimout.Seconds()) //round it to the second
	smtpInfo.ResolveTimeout = strconv.Itoa(secs) + "s"

	defaultConfigTemplate = template.Must(template.New("alertmanagerconfig").Parse(DefaultAlertmanagerConfigT))
	config := bytes.Buffer{}
	if err = defaultConfigTemplate.Execute(&config, smtpInfo); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse the config template", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "Loading default config", "confog", config.String())
	err = ioutil.WriteFile(s.AlertMgrConfigPath, config.Bytes(), 0644)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to write default alertmanager config", "err", err, "file", s.AlertMgrConfigPath)
		return err
	}
	// trigger reload of the config
	res, err := s.alertMgrApi(ctx, "POST", ReloadConfigApi, "", nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reeload alertmanager config", "err", err, "result", res)
		return err
	}
	return nil
}

// Read config from the alermgr config file.
// There are two passes here - one if a file exists and another if a file exists,
// but doesn't contain required fields
func (s *AlertMgrServer) readConfigFile(ctx context.Context) error {
	// grab config lock
	configLock.Lock()
	defer configLock.Unlock()
	// Check that the config File exists
	file, err := os.Open(s.AlertMgrConfigPath)
	if err != nil {
		// Doesn't exist - need to load up a default config
		if os.IsNotExist(err) {
			log.SpanLog(ctx, log.DebugLevelInfo, "Loading default cofig - no file found")
			if err = s.loadDefaultConfigFileLocked(ctx); err != nil {
				return err
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to access alertmanager config", "err", err, "file", s.AlertMgrConfigPath)
			return err
		}
	}
	file.Close()
	// Read config
	AlertManagerConfig, err = alertmanager_config.LoadFile(s.AlertMgrConfigPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse alertmanager config file", "err", err,
			"file", s.AlertMgrConfigPath)
		return err
	}
	// Make sure that snmp defails are present
	if AlertManagerConfig.Global.SMTPSmarthost.Host == "" || AlertManagerConfig.Global.SMTPFrom == "" {
		log.SpanLog(ctx, log.DebugLevelInfo, "Writing correct default file")
		if err = s.loadDefaultConfigFileLocked(ctx); err != nil {
			return err
		}
		// Read config
		AlertManagerConfig, err = alertmanager_config.LoadFile(s.AlertMgrConfigPath)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse alertmanager config file", "err", err,
				"file", s.AlertMgrConfigPath)
			return err
		}
	}
	return nil
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
		case <-time.After(alertRefreshInterval):
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
		end := strfmt.DateTime(time.Unix(a.ActiveAt.Seconds+int64(s.AlertResolutionTimout.Seconds()), int64(a.ActiveAt.Nanos)))
		// Add region label to differentiate these at the global level
		labels := make(map[string]string)
		for k, v := range a.Labels {
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
	data, err := s.alertMgrApi(ctx, "GET", AlertApi, "", nil)
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
	res, err := s.alertMgrApi(ctx, "POST", AlertApi, "", data)
	log.SpanLog(ctx, log.DebugLevelInfo, "marshal alerts", "alerts", string(data), "err", err, "res", res)
	return err
}

// Note - this grabs configLock
func (s *AlertMgrServer) readAlertManagerConfigAndLock(ctx context.Context) (*alertmanager_config.Config, error) {
	// grab config lock
	configLock.Lock()

	// Read config
	config, err := alertmanager_config.LoadFile(s.AlertMgrConfigPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse alertmanager config file", "err", err,
			"file", s.AlertMgrConfigPath)
		return nil, err
	}
	return config, nil
}

// Note - we should hold configLock prior to calling this function
func (s *AlertMgrServer) writeAlertManagerConfigLocked(ctx context.Context, config *alertmanager_config.Config) error {
	// write config out
	// NOTE: Alertmanager native unmarshal hides smtp password when marshalling.
	// See: https://github.com/prometheus/alertmanager/issues/1985
	// Instead our copy of the unmarshal code does not hide this. Hopefully 1985 will get addressed at some point
	err := ioutil.WriteFile(s.AlertMgrConfigPath, []byte(config.String()), 0644)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to write alertmanager config file",
			"file", s.AlertMgrConfigPath, "config", config.String())
		return err
	}
	// restart alertmanager - call api
	res, err := s.alertMgrApi(ctx, "POST", ReloadConfigApi, "", nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reload alertmanager config", "err", err, "res", res)
	}
	return err
}

func getAlertmgrReceiverName(receiver *ormapi.AlertReceiver) string {
	return receiver.Name + "-" + receiver.User + "-" + receiver.Severity + "-" + receiver.Type
}

func getRouteMatchLabelsFromAlertReceiver(in *ormapi.AlertReceiver) map[string]string {
	labels := map[string]string{}
	if in.Cloudlet.Organization != "" {
		// add labes for the cloudlet
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
func (s *AlertMgrServer) CreateReceiver(ctx context.Context, receiver *ormapi.AlertReceiver, cfg interface{}) error {
	// sanity - certain characters should not be part of the receiver name
	if strings.ContainsAny(receiver.Name, "-:") {
		return fmt.Errorf("Receiver name cannot contain dashes(\"-\"), or colons(\":\")")
	}
	// get a labelset from the receiver
	routeMatchLabels := getRouteMatchLabelsFromAlertReceiver(receiver)

	// read file and greab a lock
	AlertManagerConfig, err := s.readAlertManagerConfigAndLock(ctx)
	defer configLock.Unlock()
	if err != nil {
		return err
	}

	// We create one entry per receiver, to make it simpler
	receiverName := getAlertmgrReceiverName(receiver)
	for _, rec := range AlertManagerConfig.Receivers {
		if rec.Name == receiverName {
			log.SpanLog(ctx, log.DebugLevelInfo, "Receiver Exists - delete it first")
			return fmt.Errorf("Receiver Exists - delete it first")
		}
	}
	notifierCfg := alertmanager_config.NotifierConfig{
		VSendResolved: true,
	}
	// add a new reciever
	switch receiver.Type {
	case AlertReceiverTypeEmail:
		user, ok := cfg.(*ormapi.User)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Passed in struct is not a user struct")
			return fmt.Errorf("Passed in struct is not a user struct")
		}
		emailCfg := alertmanager_config.EmailConfig{
			NotifierConfig: notifierCfg,
			To:             user.Email,
			HTML:           alertmanagerConfigEmailHtmlTemplate,
			Headers: map[string]string{
				"Subject": alertmanagerCOnfigEmailSubjectTemplate,
			},
			Text: alertmanagerConfigEmailTextTemplate,
		}
		rec := &alertmanager_config.Receiver{
			// to make the name unique - construct it with all the fields and username
			Name:         receiverName,
			EmailConfigs: []*alertmanager_config.EmailConfig{&emailCfg},
		}
		AlertManagerConfig.Receivers = append(AlertManagerConfig.Receivers, rec)
	case AlertReceiverTypeSlack:
		// TODO - need to figure out where to add slack details; as in which struct
		fallthrough
	default:
		log.SpanLog(ctx, log.DebugLevelInfo, "Unsupported receiver type", "type", receiver.Type,
			"receiver", receiver)
		return fmt.Errorf("Invalid receiver type - %s", receiver.Type)
	}
	// add route - match labels passed in
	route := alertmanager_config.Route{
		Receiver: receiverName,
		Match:    routeMatchLabels,
		Continue: false,
	}
	AlertManagerConfig.Route.Routes = append(AlertManagerConfig.Route.Routes, &route)
	// write config out
	return s.writeAlertManagerConfigLocked(ctx, AlertManagerConfig)
}

func (s *AlertMgrServer) DeleteReceiver(ctx context.Context, receiver *ormapi.AlertReceiver) error {
	// sanity - certain characters should not be part of the receiver name
	if strings.ContainsAny(receiver.Name, "-:") {
		return fmt.Errorf("Receiver name cannot contain dashes(\"-\"), or colons(\":\")")
	}

	// read file and greab a lock
	AlertManagerConfig, err := s.readAlertManagerConfigAndLock(ctx)
	defer configLock.Unlock()
	if err != nil {
		return err
	}

	// We create one entry per receiver, to make it simpler
	receiverName := getAlertmgrReceiverName(receiver)
	for ii, rec := range AlertManagerConfig.Receivers {
		if rec.Name == receiverName {
			log.SpanLog(ctx, log.DebugLevelInfo, "Found Receiver - now delete it")
			// remove from the receivers
			AlertManagerConfig.Receivers = append(AlertManagerConfig.Receivers[:ii],
				AlertManagerConfig.Receivers[ii+1:]...)
			// remove from routes
			for jj, route := range AlertManagerConfig.Route.Routes {
				if route.Receiver == receiverName {
					AlertManagerConfig.Route.Routes = append(AlertManagerConfig.Route.Routes[:jj],
						AlertManagerConfig.Route.Routes[jj+1:]...)
					break
				}
			}
			// write config out and return
			return s.writeAlertManagerConfigLocked(ctx, AlertManagerConfig)
		}
	}
	// nothing changed - just return nil
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

func (s *AlertMgrServer) ShowReceivers(ctx context.Context, filter *ormapi.AlertReceiver) ([]ormapi.AlertReceiver, error) {
	// For show we just need a snapshot, so don't use global AlertManagerConfig
	showConfig, err := s.readAlertManagerConfigAndLock(ctx)
	configLock.Unlock()
	if err != nil {
		return nil, err
	}
	alertReceivers := []ormapi.AlertReceiver{}
	// walk config receivers and create an ormReceiver from it
	for _, rec := range showConfig.Receivers {
		// skip default reciever
		if rec.Name == "default" {
			continue
		}
		receiver, err := getAlertReceiverFromName(rec.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Unable to parse receiver", "receiver", rec, "err", err)
			continue
		}
		// find Route associated with this receiver
		for _, route := range showConfig.Route.Routes {
			if route.Receiver == rec.Name {
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
				alertReceivers = append(alertReceivers, *receiver)
			}
		}
	}
	return alertReceivers, nil
}

// Common function to send an api call to alertmanager
func (s *AlertMgrServer) alertMgrApi(ctx context.Context, method, api, options string, payload []byte) ([]byte, error) {
	url := s.AlertMrgAddr + "/" + api
	if options != "" {
		url += "?" + options
	}
	client := http.DefaultClient
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to create a new alerts request", "err", err, "url", url)
		return nil, err
	}
	req.Header.Set("User-Agent", s.McAlertmanagerAgentName)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to send request to the alertmanager", "err", err, "request", req)
		return nil, err
	}
	defer resp.Body.Close()
	// HTTP status 2xx is ok
	if resp.StatusCode/100 != 2 {
		log.SpanLog(ctx, log.DebugLevelInfo, "Alertmanager responded with an error", "request", req, "response", resp)
		return nil, fmt.Errorf("bad response status %s", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to read response body", "request", req, "response", resp)
		return nil, err
	}
	return body, nil
}
