package orm

import (
	fmt "fmt"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
)

type AlertManagerContext struct {
	claims *UserClaims
}

// Create alert receiver api handler
func CreateAlertReceiver(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	log.SpanLog(ctx, log.DebugLevelInfo, "Create Alertmanager Receiver", "context", c, "claims", claims)
	in := ormapi.AlertReceiver{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	// sanity check
	if in.Name == "" {
		return setReply(c, fmt.Errorf("Receiver name has to be specified"), nil)
	}
	if !cloudcommon.IsAlertSeverityValid(in.Severity) {
		return setReply(c, fmt.Errorf("Alert severity has to be one of %s", cloudcommon.GetValidAlertSeverityString()), nil)
	}
	// user is derived from the token
	if in.User != "" {
		return setReply(c, fmt.Errorf("User is not specifiable, current logged in user will be used"), nil)
	}
	in.User = claims.Username
	if in.Cloudlet.Organization == "" && in.AppInst.AppKey.Organization == "" {
		return setReply(c,
			fmt.Errorf("Either cloudlet, or app instance details have to be specified"), nil)
	}
	// Check that user is allowed to access either of the orgs
	if in.Cloudlet.Organization != "" {
		if err := authorized(ctx, claims.Username, in.Cloudlet.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	}
	if in.AppInst.AppKey.Organization != "" {
		if err := authorized(ctx, claims.Username, in.AppInst.AppKey.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	}

	switch in.Type {
	case alertmgr.AlertReceiverTypeEmail:
		// if an email is not specified send to an email on file
		if in.Email == "" {
			in.Email = claims.Email
		}
		err = AlertManagerServer.CreateReceiver(ctx, &in)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to create a receiver", "err", err)
			return setReply(c, fmt.Errorf("Unable to create a receiver - %s", err.Error()),
				nil)
		}
	case alertmgr.AlertReceiverTypeSlack:
		// TODO - retrieve org slack channel from vault, for now require slack details
		if in.SlackWebhook == "" || in.SlackChannel == "" {
			log.SpanLog(ctx, log.DebugLevelInfo, "Slack details are missing", "receiver", in)
			return setReply(c, fmt.Errorf("Slack URL, or channel are missing"),
				nil)
		}
		err = AlertManagerServer.CreateReceiver(ctx, &in)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to create a receiver", "err", err)
			return setReply(c, fmt.Errorf("Unable to create a receiver - %s", err.Error()),
				nil)
		}
	default:
		log.SpanLog(ctx, log.DebugLevelInfo, "type of a receiver is invalid")
		return setReply(c, fmt.Errorf("Receiver type invalid"), nil)
	}
	return nil
}

// Delete alert receiver api handler
func DeleteAlertReceiver(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	log.SpanLog(ctx, log.DebugLevelInfo, "Delete Alertmanager Receiver", "context", c, "claims", claims)
	in := ormapi.AlertReceiver{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}

	// user is derived from the token
	if in.User != "" {
		return setReply(c, fmt.Errorf("User is not specifiable, current logged in user will be used"), nil)
	}
	in.User = claims.Username

	// Check that user is allowed to access either of the orgs
	if in.Cloudlet.Organization != "" {
		if err := authorized(ctx, claims.Username, in.Cloudlet.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	}
	if in.AppInst.AppKey.Organization != "" {
		if err := authorized(ctx, claims.Username, in.AppInst.AppKey.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	}
	// If the user is not specified look for the alertname for the user that's logged in
	err = AlertManagerServer.DeleteReceiver(ctx, &in)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to delete a receiver", "err", err)
		return setReply(c, fmt.Errorf("Unable to delete a receiver - %s", err.Error()),
			nil)
	}
	return nil
}

// Show alert receivers api handler
func ShowAlertReceiver(c echo.Context) error {
	alertRecs := []ormapi.AlertReceiver{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Show Alertmanager Receivers", "context", c, "claims", claims)

	receivers, err := AlertManagerServer.ShowReceivers(ctx, nil)
	if err != nil {
		return err
	}
	for ii := range receivers {
		if receivers[ii].Cloudlet.Organization != "" {
			if err := authorized(ctx, claims.Username, receivers[ii].Cloudlet.Organization,
				ResourceAlert, ActionView); err == nil {
				alertRecs = append(alertRecs, receivers[ii])
			}
		} else {
			if err := authorized(ctx, claims.Username, receivers[ii].AppInst.AppKey.Organization,
				ResourceAlert, ActionView); err == nil {
				alertRecs = append(alertRecs, receivers[ii])
			}
		}
	}
	return setReply(c, err, alertRecs)
}
