package federationmgmt

import (
	"fmt"
	"net/http"
)

const (
	ApiRoot      = "operatorplatform/federation/v1"
	CallbackRoot = "operatorplatform/fedcallbacks/v1"

	// callback urls, used by both MC and FRM
	PartnerStatusEventPath           = CallbackRoot + "/onPartnerStatusEvent"
	PartnerZoneResourceUpdatePath    = CallbackRoot + "/onZoneResourceUpdateEvent"
	PartnerAppOnboardStatusEventPath = CallbackRoot + "/onApplicationOnboardStatusEvent"
	PartnerInstanceStatusEventPath   = CallbackRoot + "/onInstanceStatusEvent"
	PartnerResourceStatusChangePath  = CallbackRoot + "/onResourceStatusChangeEvent"

	PathVarAppInstUniqueId = "appInstUniqueId"

	AppInstStatePending     = "PENDING"
	AppInstStateReady       = "READY"
	AppInstStateFailed      = "FAILED"
	AppInstStateTerminating = "TERMINATING"
)

func PathCreateAppInst(fedCtxId string) (string, string) {
	return http.MethodPost, fmt.Sprintf("/%s/application/lcm", fedCtxId)
}

func PathGetAppInst(fedCtxId, appId, appInstId, zoneId string) (string, string) {
	return http.MethodGet, fmt.Sprintf("/%s/application/lcm/app/%s/instance/%s/zone/%s", fedCtxId, appId, appInstId, zoneId)
}
