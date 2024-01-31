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

package pfutils

import (
	"context"
	"fmt"
	"os"
	"plugin"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/platforms"
)

var solib = ""
var GetPlatformFunc func(plat string) (pf.Platform, error)

func GetClusterSvc(ctx context.Context, pluginRequired bool) (pf.ClusterSvc, error) {
	return platforms.GetClusterSvc()
}

func loadPlugin(ctx context.Context) (*plugin.Plugin, error) {
	// Load platform from plugin
	if solib == "" {
		solib = os.Getenv("GOPATH") + "/plugins/platforms.so"
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "Loading plugin", "plugin", solib)
	plug, err := plugin.Open(solib)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "failed to load plugin", "plugin", solib, "error", err)
		return nil, fmt.Errorf("failed to load plugin %s, err: %v", solib, err)
	}
	return plug, nil
}
