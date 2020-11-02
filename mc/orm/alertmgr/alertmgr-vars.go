package alertmgr

import (
	"time"
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

var alertmanagerConfigEmailHtmlTemplate = `{{ template "email.html" . }}`

// NOTE - below only works for an appInst alert, not a cloudlet alert.
var alertmanagerConfigEmailSubjectTemplate = `{{ template "email.subject" . }}`
var alertmanagerConfigEmailTextTemplate = `{{ template "email.text" . }}`

var alertmanagerConfigSlackTitle = `{{ template "slack.title" . }}`

var alertmanagerConfigSlackText = `{{ template "slack.text" . }}`
var alertmanagerConfigSlackFallback = `{{ template "slack.fallback" . }}`

var alertmanagerConfigSlackTitleLink = `{{ template "console.link" . }}`

var alertmanagerConfigSlackIcon = "https://www.mobiledgex.com/img/logo.svg"

const (
	AlertReceiverTypeEmail    = "email"
	AlertReceiverTypeSlack    = "slack"
	AlertMgrSlackWebhookToken = "<hidden>"
)

const (
	AlertApi               = "/api/v2/alerts"
	ReceiverApi            = "/api/v2/receivers"
	SilenceApi             = "/api/v2/silences"
	ReloadConfigApi        = "/-/reload"
	mobiledgeXReceiversApi = "/api/v3/receivers"
	mobiledgeXReceiverApi  = "/api/v3/receiver"
)
