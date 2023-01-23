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

package ctrlclient

import (
	"context"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
)

func RunCommandValidateInput(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.ExecRequest) error {
	if obj.Cmd != nil {
		sanitizedCmd, err := util.RunCommandSanitize(obj.Cmd.Command)
		if err != nil {
			return err
		}
		obj.Cmd.Command = sanitizedCmd
	}
	return nil
}

func HandleFedAppInstEventObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.FedAppInstEvent, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewAppInstApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.HandleFedAppInstEvent(ctx, obj)
}
