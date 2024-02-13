// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	CallbackNotSupported  = "NOT_SUPPORTED"
	NoCallbackApiKey      = "NO_CALLBACK_API_KEY"
	NoCallbackApiKeyError = "no callback API key"
)

func PathCreateAppInst(fedCtxId string) (string, string) {
	return http.MethodPost, fmt.Sprintf("/%s/application/lcm", fedCtxId)
}

func PathGetAppInst(fedCtxId, appId, appInstId, zoneId string) (string, string) {
	return http.MethodGet, fmt.Sprintf("/%s/application/lcm/app/%s/instance/%s/zone/%s", fedCtxId, appId, appInstId, zoneId)
}
