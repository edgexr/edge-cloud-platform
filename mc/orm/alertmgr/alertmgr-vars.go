package alertmgr

import (
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var alertRefreshInterval = 30 * time.Second

// Notes on the default values:
//   resolve_timeout - since we refresh  this every minute, 3*mins should be sufficient
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

// This is mostly taken from https://github.com/prometheus/alertmanager/blob/master/template/default.tmpl with minor modifications
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

const (
	AlertApi               = "/api/v2/alerts"
	ReceiverApi            = "/api/v2/receivers"
	SilenceApi             = "/api/v2/silences"
	ReloadConfigApi        = "/-/reload"
	mobiledgeXReceiversApi = "/api/v3/receivers"
	mobiledgeXReceiverApi  = "/api/v3/receiver"
)
