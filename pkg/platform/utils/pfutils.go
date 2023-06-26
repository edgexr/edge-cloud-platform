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
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/platforms"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
)

var solib = ""
var GetPlatformFunc func(plat string) (pf.Platform, error)

func GetPlatform(ctx context.Context, plat string, setVersionProps func(context.Context, map[string]string)) (pf.Platform, error) {
	return platforms.GetPlatform(plat)
}

func GetClusterSvc(ctx context.Context, pluginRequired bool) (pf.ClusterSvc, error) {
	return platforms.GetClusterSvc()
}

// GetAppInstId returns a string for this AppInst that is likely to be
// unique within the region. It does not guarantee uniqueness.
// The delimiter '.' is removed from the AppInstId so that it can be used
// to append further strings to this ID to build derived unique names.
// Salt can be used by the caller to add an extra field if needed
// to ensure uniqueness. In all cases, any requirements for uniqueness
// must be guaranteed by the caller. Name sanitization for the platform is performed
func GetAppInstId(ctx context.Context, appInst *edgeproto.AppInst, app *edgeproto.App, salt string, platformType string) (string, error) {
	fields := []string{}

	cloudletPlatform, err := GetPlatform(ctx, platformType, nil)
	if err != nil {
		return "", err
	}
	name := util.DNSSanitize(appInst.Key.Name)
	dev := util.DNSSanitize(appInst.Key.Organization)
	fields = append(fields, dev, name)

	loc := util.DNSSanitize(appInst.Key.CloudletKey.Name)
	fields = append(fields, loc)

	oper := util.DNSSanitize(appInst.Key.CloudletKey.Organization)
	fields = append(fields, oper)

	if salt != "" {
		salt = util.DNSSanitize(salt)
		fields = append(fields, salt)
	}
	return cloudletPlatform.NameSanitize(strings.Join(fields, "-")), nil
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
