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

package orm

import (
	fmt "fmt"
	"strings"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
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
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelInfo, "Create Alertmanager Receiver", "context", c, "claims", claims)
	in := ormapi.AlertReceiver{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	// sanity check
	if in.Name == "" {
		return fmt.Errorf("Receiver name has to be specified")
	}
	// Name validation
	if !util.ValidName(in.Name) {
		return fmt.Errorf("Receiver name is invalid")
	}

	if !cloudcommon.IsAlertSeverityValid(in.Severity) {
		return fmt.Errorf("Alert severity has to be one of %s", cloudcommon.GetValidAlertSeverityString())
	}
	// user is derived from the token
	if in.User != "" {
		return fmt.Errorf("User is not specifiable, current logged in user will be used")
	}
	in.User = claims.Username
	if in.Cloudlet.Organization == "" &&
		in.AppInst.AppKey.Organization == "" &&
		in.AppInst.ClusterInstKey.Organization == "" &&
		!isAdmin(ctx, claims.Username) {
		return fmt.Errorf("Either cloudlet, cluster or app instance details have to be specified")
	}
	if in.Cloudlet.Organization != "" {
		// Check that user is allowed to access either of the orgs
		if err := authorized(ctx, claims.Username, in.Cloudlet.Organization,
			ResourceAlert, ActionView); err != nil {
			return err
		}
		if !in.AppInst.Matches(&edgeproto.AppInstKey{}) {
			return fmt.Errorf("AppInst details cannot be specified if this receiver is for cloudlet alerts")
		}
	} else {
		if !in.Cloudlet.Matches(&edgeproto.CloudletKey{}) {
			return fmt.Errorf("Cloudlet details cannot be specified if this receiver is for appInst or cluster alerts")
		}
	}
	if in.AppInst.AppKey.Organization != "" {
		if err := authorized(ctx, claims.Username, in.AppInst.AppKey.Organization,
			ResourceAlert, ActionView); err != nil {
			return err
		}
	} else if in.AppInst.ClusterInstKey.Organization != "" {
		// It could be just a cluster-based alert receiver
		if err := authorized(ctx, claims.Username, in.AppInst.ClusterInstKey.Organization,
			ResourceAlert, ActionView); err != nil {
			return err
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
				return fmt.Errorf("Receiver email is invalid")
			}
		}
	case alertmgr.AlertReceiverTypeSlack:
		// TODO - retrieve org slack channel from vault, for now require slack details
		if in.SlackWebhook == "" || in.SlackChannel == "" {
			log.SpanLog(ctx, log.DebugLevelInfo, "Slack details are missing", "receiver", in)
			return fmt.Errorf("Both slack URL and slack channel must be specified")
		}
		// make sure channel has "#" as a prefix
		// this allows channel to be specified without # on the api
		if !strings.HasPrefix(in.SlackChannel, "#") {
			in.SlackChannel = "#" + in.SlackChannel
		}
	case alertmgr.AlertReceiverTypePagerDuty:
		if in.PagerDutyIntegrationKey == "" {
			return fmt.Errorf("PagerDuty Integration Key must be present")
		}
		if len(in.PagerDutyIntegrationKey) != alertmgr.PagerDutyIntegrationKeyLen {
			return fmt.Errorf("PagerDuty Integration Key must contain %d characters", alertmgr.PagerDutyIntegrationKeyLen)
		}
	default:
		log.SpanLog(ctx, log.DebugLevelInfo, "type of a receiver is invalid")
		return fmt.Errorf("Receiver type invalid")
	}
	err = AlertManagerServer.CreateReceiver(ctx, &in)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to create a receiver", "err", err)
		return fmt.Errorf("Unable to create a receiver - %s", err.Error())
	}
	return ormutil.SetReply(c, ormutil.Msg("Alert receiver created successfully"))
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
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelInfo, "Delete Alertmanager Receiver", "context", c, "claims", claims)
	in := ormapi.AlertReceiver{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}

	org := getOrgForReceiver(&in)
	// if a user is specified we need to make sure this user has permissions to manage the users in the org
	if in.User != "" && in.User != claims.Username {
		if org == "" {
			return fmt.Errorf("Org details must be present to manage a specific receiver")
		}
		// check if this user is authorized to manage users in the org
		if err := authorized(ctx, claims.Username, org,
			ResourceUsers, ActionManage); err != nil {
			return err
		}

		// also check that the user specified is is part of the org
		if err := authorized(ctx, in.User, org, ResourceAlert, ActionView); err != nil {
			return err
		}

	} else {
		in.User = claims.Username
	}

	// Check that user is allowed to access either of the orgs
	if org != "" {
		if err := authorized(ctx, claims.Username, org, ResourceAlert, ActionView); err != nil {
			return err
		}
	}

	// If the user is not specified look for the alertname for the user that's logged in
	err = AlertManagerServer.DeleteReceiver(ctx, &in)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to delete a receiver", "err", err)
		return fmt.Errorf("Unable to delete a receiver - %s", err.Error())
	}
	return ormutil.SetReply(c, ormutil.Msg("Alert receiver deleted successfully"))
}

// Show alert receivers api handler
func ShowAlertReceiver(c echo.Context) error {
	alertRecs := []ormapi.AlertReceiver{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Show Alertmanager Receivers", "context", c, "claims", claims)

	filter := ormapi.AlertReceiver{}
	if c.Request().ContentLength > 0 {
		if err := c.Bind(&filter); err != nil {
			return ormutil.BindErr(err)
		}
	}

	if filter.SlackWebhook != "" {
		return fmt.Errorf("Slack URL is not specifiable as a filter")
	}

	allowedOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceAlert, ActionView)
	isAdmin := false
	if err != nil {
		return err
	}
	// check for a user with no orgs
	if len(allowedOrgs) == 0 {
		return echo.ErrForbidden
	}
	if _, found := allowedOrgs[""]; found {
		isAdmin = true
	}
	// Admin users can specify a user, or see all the receivers
	if !isAdmin {
		// If a user is a user-management role for the org in the filter allow user to be specified
		if filter.User != "" && filter.User != claims.Username {
			filterOrg := getOrgForReceiver(&filter)
			if filterOrg == "" {
				return fmt.Errorf("Org details must be present to see receivers")
			}
			// check if this user is authorized to manage users in the org
			if err := authorized(ctx, claims.Username, filterOrg, ResourceUsers, ActionManage); err != nil {
				return err
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
		if _, found := allowedOrgs[org]; found || isAdmin {
			alertRecs = append(alertRecs, receivers[ii])
		}
	}
	return ormutil.SetReply(c, alertRecs)
}
