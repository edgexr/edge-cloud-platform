package cloudcommon

import (
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

const (
	// Important: key strings used here for grpc metadata keys
	// MUST be lower-case.
	CallerAutoProv         = "caller-auto-prov"
	AutoProvReason         = "auto-prov-reason"
	AutoProvReasonDemand   = "demand"
	AutoProvReasonMinMax   = "minmax"
	AutoProvReasonOrphaned = "orphaned"
	AutoProvPolicyName     = "auto-prov-policy-name"
)

func AutoProvCloudletOnline(cloudletInfo *edgeproto.CloudletInfo) bool {
	// Transitional states are considered "online".
	if cloudletInfo.State == edgeproto.CloudletState_CLOUDLET_STATE_OFFLINE {
		return false
	}
	return true
}

func AutoProvAppInstOnline(appInst *edgeproto.AppInst, cloudletInfo *edgeproto.CloudletInfo) bool {
	// Transitional states are considered "online"...but health check
	// doesn't actually have transitional states, except perhaps unknown.
	appInstOnline := false
	if appInst.HealthCheck == edgeproto.HealthCheck_HEALTH_CHECK_UNKNOWN ||
		appInst.HealthCheck == edgeproto.HealthCheck_HEALTH_CHECK_OK {
		appInstOnline = true
	}
	return appInstOnline && AutoProvCloudletOnline(cloudletInfo)
}

func AppInstBeingDeleted(inst *edgeproto.AppInst) bool {
	if inst.State == edgeproto.TrackedState_DELETE_REQUESTED || inst.State == edgeproto.TrackedState_DELETING || inst.State == edgeproto.TrackedState_DELETE_PREPARE || inst.State == edgeproto.TrackedState_NOT_PRESENT {
		return true
	}
	return false
}
