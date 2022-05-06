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

package openstack

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
)

func (o *OpenstackPlatform) initDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("oscmd", o.runOsCmd)
}

func (o *OpenstackPlatform) runOsCmd(ctx context.Context, req *edgeproto.DebugRequest) string {
	if req.Args == "" {
		return "please specify openstack command in args field"
	}
	rd := csv.NewReader(strings.NewReader(req.Args))
	rd.Comma = ' '
	args, err := rd.Read()
	if err != nil {
		return fmt.Sprintf("failed to split args string, %v", err)
	}
	out, err := o.TimedOpenStackCommand(ctx, args[0], args[1:]...)
	if err != nil {
		return fmt.Sprintf("openstack command failed: %v, %s", err, string(out))
	}
	return string(out)
}
