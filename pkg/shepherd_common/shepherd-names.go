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

package shepherd_common

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/proxy"
)

func GetProxyKey(appInstKey *edgeproto.AppInstKey) string {
	return appInstKey.Name + "-" + appInstKey.Organization
}

func ShouldRunEnvoy(app *edgeproto.App, appInst *edgeproto.AppInst) bool {
	log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app.Key)
	needEnvoy, _ := proxy.CheckProtocols("", appInst.MappedPorts)
	if !needEnvoy {
		log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app.Key, "needEnvoy", needEnvoy)
		return false
	}
	if app.InternalPorts || app.AccessType != edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
		log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app, "appCheck", false)
		return false
	}
	log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app.Key, "ok", true)
	return true
}
