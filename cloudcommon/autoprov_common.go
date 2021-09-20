package cloudcommon

import (
	"fmt"

	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
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
	AccessKeyData          = "access-key-data"
	AccessKeySig           = "access-key-sig"
	VaultKeySig            = "vault-key-sig"
)

var AutoProvMinAlreadyMetError = fmt.Errorf("Create to satisfy min already met, ignoring")

func AutoProvCloudletInfoOnline(cloudletInfo *edgeproto.CloudletInfo) bool {
	// Transitional states are considered "online".
	if cloudletInfo.State == dme.CloudletState_CLOUDLET_STATE_OFFLINE {
		return false
	}
	return true
}

func AutoProvCloudletOnline(cloudlet *edgeproto.Cloudlet) bool {
	// any maintenance state is considered offline
	if cloudlet.MaintenanceState != dme.MaintenanceState_NORMAL_OPERATION {
		return false
	}
	return true
}

func AutoProvAppInstOnline(appInst *edgeproto.AppInst, cloudletInfo *edgeproto.CloudletInfo, cloudlet *edgeproto.Cloudlet) bool {
	// Transitional states are considered "online"...but health check
	// doesn't actually have transitional states, except perhaps unknown.
	appInstOnline := false
	if appInst.HealthCheck == dme.HealthCheck_HEALTH_CHECK_UNKNOWN ||
		appInst.HealthCheck == dme.HealthCheck_HEALTH_CHECK_OK {
		appInstOnline = true
	}
	return appInstOnline && AutoProvCloudletInfoOnline(cloudletInfo) && AutoProvCloudletOnline(cloudlet)
}

func AppInstBeingDeleted(inst *edgeproto.AppInst) bool {
	if inst.State == edgeproto.TrackedState_DELETE_REQUESTED || inst.State == edgeproto.TrackedState_DELETING || inst.State == edgeproto.TrackedState_DELETE_PREPARE || inst.State == edgeproto.TrackedState_DELETE_DONE || inst.State == edgeproto.TrackedState_NOT_PRESENT {
		return true
	}
	return false
}

// Cluster name to trigger using an existing free reservable ClusterInst
// or creating a new one automatically.
// Because this name is always part of the AppInstKey in etcd,
// and because AutoProv will only ever instantiate once instance
// of an App per cloudlet, there are really no uniqueness requirements
// on this name.
// Additionally any objects instantiated at the infra level that
// are independent of the AppInst key should be using the
// real cluster name from the ClusterInst object.
var AutoProvClusterName = AutoClusterPrefix + "-autoprov"
