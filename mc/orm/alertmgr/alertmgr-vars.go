package alertmgr

import (
	"time"
)

const (
	// Notes on the default values:
	//   resolve_timeout - since we refresh  this every minute, 3*mins should be sufficient
	//   group_wait - since we are not grouping alerts right now, 1 sec for instant alert send
	//   group_interval - since we are grouping this setting doesn't do anything, but we might use it in the future
	//   repeat_interval - re-send every 2hrs until resolved
	DefaultAlertmanagerConfigT = `global:
  resolve_timeout: {{.ResolveTimeout}}
  smtp_from: "{{.Email}}"
  smtp_smarthost: {{.Smtp}}:{{.Port}}
  smtp_auth_username: "{{.User}}"
  smtp_auth_identity: "{{.User}}"
  smtp_auth_password: "{{.Token}}"
  {{if .Tls}}smtp_require_tls: {{.Tls}}{{end}}
  {{if .PagerDutyUrl}}pagerduty_url: {{.PagerDutyUrl}}{{end}}
templates:
  - '/etc/alertmanager/templates/alertmanager.tmpl'
route:
  group_by: ['...']
  group_wait: 0s
  group_interval: 1s
  repeat_interval: 2h
  receiver: default
receivers:
- name: default
`

	AlertReceiverTypeEmail     = "email"
	AlertReceiverTypeSlack     = "slack"
	AlertReceiverTypePagerDuty = "pagerduty"
	AlertMgrDisplayHidden      = "<hidden>"

	AlertApi               = "/api/v2/alerts"
	ReceiverApi            = "/api/v2/receivers"
	SilenceApi             = "/api/v2/silences"
	ReloadConfigApi        = "/-/reload"
	mobiledgeXReceiversApi = "/api/v3/receivers"
	mobiledgeXReceiverApi  = "/api/v3/receiver"
)

var (
	alertRefreshInterval                = 30 * time.Second
	alertmanagerConfigEmailHtmlTemplate = `{{ template "email.html" . }}`

	// NOTE - below only works for an appInst alert, not a cloudlet alert.
	alertmanagerConfigEmailSubjectTemplate = `{{ template "status.title" . }}`
	alertmanagerConfigEmailTextTemplate    = `{{ template "email.text" . }}`

	alertmanagerConfigSlackTitle = `{{ template "status.title" . }}`

	alertmanagerConfigSlackText     = `{{ template "slack.text" . }}`
	alertmanagerConfigSlackFallback = `{{ template "slack.fallback" . }}`

	alertmanagerConfigSlackTitleLink = `{{ template "console.link" . }}`

	alertmanagerConfigSlackIcon = "https://www.mobiledgex.com/img/logo.svg"

	alertmanagerConfigPagerDutyClient      = "MobiledgeX Monitoring"
	alertmanagerConfigPagerDutyDescription = `{{ template "common.title" . }}`
	alertmanagerConfigPagerDutyDetails     = map[string]string{
		"firing":   `{{ template "pagerduty.instances" .Alerts.Firing }}`,
		"resolved": `{{ template "pagerduty.instances" .Alerts.Resolved }}`,
	}

	PagerDutyIntegrationKeyLen = 32
)
