## Sync MC org status with the Community Slack Workspace

### Run

This app requires the following environment variables:

   * `SLACK_TOKEN`: A slack API token with the following OAuth scopes: `channels:read`, `groups:read`, `groups:write`, `users:read`, and `users:read.email`
   * `SLACK_LEGACY_TOKEN`: A slack legacy API token speicifically to send invites to new developers. This uses a private Slack API which works only with legacy tokens.
   * `MC_USER`: An MC user account with AdminViewer privileges
   * `MC_PASS`: The password for the MC account
   * `LOG_WEBHOOK`: A Slack incoming webhook to post alerts from this app

```
docker run --rm \
	-e SLACK_TOKEN="xoxp-..." \
	-e SLACK_LEGACY_TOKEN="xoxp-..." \
	-e MC_USER=mcviewer \
	-e MC_PASS="XXX" \
	-e LOG_WEBHOOK="https://hooks.slack.com/services/T9..." \
	registry.mobiledgex.net:5000/mobiledgex/slack-org-mgmt:VERSION
```
