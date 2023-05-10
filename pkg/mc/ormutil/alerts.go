package ormutil

import (
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

func GetOrgAndScopeForReceiver(in *ormapi.AlertReceiver) (string, string) {
	if in == nil {
		return "", ""
	}
	org := ""
	scope := ""

	// order is important here, since multiple orgs may be
	// present in certain cases.
	if in.AppInstKey.Organization != "" {
		// developer
		org = in.AppInstKey.Organization
		scope = cloudcommon.AlertScopeApp
	} else if in.AppKey.Organization != "" {
		// developer
		org = in.AppKey.Organization
		scope = cloudcommon.AlertScopeApp
	} else if in.ClusterKey.Organization != "" {
		// developer
		org = in.ClusterKey.Organization
		scope = cloudcommon.AlertScopeApp
	} else if in.AppInstKey.CloudletKey.Organization != "" {
		// operator
		org = in.AppInstKey.CloudletKey.Organization
		scope = cloudcommon.AlertScopeCloudlet
	} else {
		// Default to Platform scope when no org (from cloudlet/appkey/clusterinstkey) is specified
		// Only admin can see platform scope alerts.
		scope = cloudcommon.AlertScopePlatform
	}
	return org, scope
}
