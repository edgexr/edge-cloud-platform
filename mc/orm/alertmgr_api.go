package orm

import (
	fmt "fmt"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
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
	// Name validation
	if !util.ValidName(in.Name) {
		return setReply(c, fmt.Errorf("Receiver name is invalid"), nil)
	}

	if !cloudcommon.IsAlertSeverityValid(in.Severity) {
		return setReply(c, fmt.Errorf("Alert severity has to be one of %s", cloudcommon.GetValidAlertSeverityString()), nil)
	}
	// user is derived from the token
	if in.User != "" {
		return setReply(c, fmt.Errorf("User is not specifiable, current logged in user will be used"), nil)
	}
	in.User = claims.Username
	if in.Cloudlet.Organization == "" &&
		in.AppInst.AppKey.Organization == "" &&
		in.AppInst.ClusterInstKey.Organization == "" {
		return setReply(c,
			fmt.Errorf("Either cloudlet, cluster or app instance details have to be specified"), nil)
	}
	if in.Cloudlet.Organization != "" {
		// Check that user is allowed to access either of the orgs
		if err := authorized(ctx, claims.Username, in.Cloudlet.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
		if !in.AppInst.Matches(&edgeproto.AppInstKey{}) {
			return setReply(c,
				fmt.Errorf("AppInst details cannot be specified if this receiver is for cloudlet alerts"), nil)
		}
	} else {
		if !in.Cloudlet.Matches(&edgeproto.CloudletKey{}) {
			return setReply(c,
				fmt.Errorf("Cloudlet details cannot be specified if this receiver is for appInst or cluster alerts"), nil)
		}
	}
	if in.AppInst.AppKey.Organization != "" {
		if err := authorized(ctx, claims.Username, in.AppInst.AppKey.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	} else if in.AppInst.ClusterInstKey.Organization != "" {
		// It could be just a cluster-based alert receiver
		if err := authorized(ctx, claims.Username, in.AppInst.ClusterInstKey.Organization,
			ResourceAlert, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	}

	switch in.Type {
	case alertmgr.AlertReceiverTypeEmail:
		// if an email is not specified send to an email on file
		if in.Email == "" {
			in.Email = claims.Email
		} else {
			// validate email
			if !util.ValidEmail(in.Email) {
				return setReply(c, fmt.Errorf("Receiver email is invalid"), nil)
			}
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
			return setReply(c, fmt.Errorf("Both slack URL and slack channel must be specified"),
				nil)
		}
		// make sure channel has "#" as a prefix
		// this allows channel to be specified without # on the api
		if !strings.HasPrefix(in.SlackChannel, "#") {
			in.SlackChannel = "#" + in.SlackChannel
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
	return setReply(c, nil, Msg("Alert receiver created successfully"))
}

func getOrgForReceiver(in *ormapi.AlertReceiver) string {
	if in == nil {
		return ""
	}
	org := ""

	if in.Cloudlet.Organization != "" {
		org = in.Cloudlet.Organization
	} else if in.AppInst.AppKey.Organization != "" {
		org = in.AppInst.AppKey.Organization
	} else if in.AppInst.ClusterInstKey.Organization != "" {
		org = in.AppInst.ClusterInstKey.Organization
	}
	return org
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

	org := getOrgForReceiver(&in)
	// if a user is specified we need to make sure this user has permissions to manage the users in the org
	if in.User != "" && in.User != claims.Username {
		if org == "" {
			return setReply(c, fmt.Errorf("Org details must be present to manage a specific receiver"), nil)
		}
		// check if this user is authorized to manage users in the org
		if err := authorized(ctx, claims.Username, org,
			ResourceUsers, ActionManage); err != nil {
			return setReply(c, err, nil)
		}
	} else {
		in.User = claims.Username
	}

	// Check that user is allowed to access either of the orgs
	if org != "" {
		if err := authorized(ctx, claims.Username, org, ResourceAlert, ActionView); err != nil {
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
	return setReply(c, err, Msg("Alert receiver deleted successfully"))
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

	filter := ormapi.AlertReceiver{}
	if c.Request().ContentLength > 0 {
		if err := c.Bind(&filter); err != nil {
			return bindErr(c, err)
		}
	}

	if filter.SlackWebhook != "" {
		return setReply(c, fmt.Errorf("Slack URL is not specifiable as a filter"), nil)
	}

	// Admin users can specify a user, or see all the receivers
	adminUser, _ := isUserAdmin(ctx, claims.Username)
	if !adminUser {
		// If a user is a user-management role for the org in the filter allow user to be specified
		if filter.User != "" && filter.User != claims.Username {
			filterOrg := getOrgForReceiver(&filter)
			if filterOrg == "" {
				return setReply(c, fmt.Errorf("Org details must be present to see receivers"), nil)
			}
			// check if this user is authorized to manage users in the org
			if err := authorized(ctx, claims.Username, filterOrg, ResourceUsers, ActionManage); err != nil {
				return setReply(c, err, nil)
			}
		} else {
			filter.User = claims.Username
		}
	}
	receivers, err := AlertManagerServer.ShowReceivers(ctx, &filter)
	if err != nil {
		return err
	}
	for ii := range receivers {
		org := getOrgForReceiver(&receivers[ii])
		if err := authorized(ctx, claims.Username, org, ResourceAlert, ActionView); err == nil {
			alertRecs = append(alertRecs, receivers[ii])
		}
	}
	return setReply(c, err, alertRecs)
}
