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

package main

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type DebugApi struct{}

var debugApi = DebugApi{}

func (s *DebugApi) EnableDebugLevels(req *edgeproto.DebugRequest, cb edgeproto.DebugApi_EnableDebugLevelsServer) error {
	req.Cmd = svcnode.EnableDebugLevels
	return s.RunDebug(req, cb)
}

func (s *DebugApi) DisableDebugLevels(req *edgeproto.DebugRequest, cb edgeproto.DebugApi_DisableDebugLevelsServer) error {
	req.Cmd = svcnode.DisableDebugLevels
	return s.RunDebug(req, cb)
}

func (s *DebugApi) ShowDebugLevels(req *edgeproto.DebugRequest, cb edgeproto.DebugApi_ShowDebugLevelsServer) error {
	req.Cmd = svcnode.ShowDebugLevels
	return s.RunDebug(req, cb)
}

func (s *DebugApi) RunDebug(req *edgeproto.DebugRequest, cb edgeproto.DebugApi_RunDebugServer) error {
	log.SpanLog(cb.Context(), log.DebugLevelApi, "RunDebug", "cmd", req.Cmd)
	return nodeMgr.Debug.DebugRequest(req, cb)
}
