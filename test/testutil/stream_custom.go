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

package testutil

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

type AllDataStreamOut struct {
	StreamAppInsts     []StreamAppInst
	StreamClusterInsts []StreamClusterInst
	StreamCloudlets    []StreamCloudlet
}

type StreamAppInst struct {
	Key  edgeproto.AppInstKey
	Msgs []edgeproto.Result
}

type StreamClusterInst struct {
	Key  edgeproto.ClusterKey
	Msgs []edgeproto.Result
}

type StreamCloudlet struct {
	Key  edgeproto.CloudletKey
	Msgs []edgeproto.Result
}

func RunAllDataStreamApis(run *Run, in *edgeproto.AllData, out *AllDataStreamOut) {
	run.Mode = "streamappinst"
	for _, appInst := range in.AppInstances {
		appInstKeys := []edgeproto.AppInstKey{appInst.Key}
		outMsgs := [][]edgeproto.Result{}
		run.StreamObjApi_AppInstKey(&appInstKeys, nil, &outMsgs)
		outObj := StreamAppInst{Key: appInst.Key}
		for _, objsMsgs := range outMsgs {
			outObj.Msgs = objsMsgs
		}
		out.StreamAppInsts = append(out.StreamAppInsts, outObj)
	}

	run.Mode = "streamclusterinst"
	for _, clusterInst := range in.ClusterInsts {
		clusterKeys := []edgeproto.ClusterKey{clusterInst.Key}
		outMsgs := [][]edgeproto.Result{}
		run.StreamObjApi_ClusterKey(&clusterKeys, nil, &outMsgs)
		outObj := StreamClusterInst{Key: clusterInst.Key}
		for _, objsMsgs := range outMsgs {
			outObj.Msgs = objsMsgs
		}
		out.StreamClusterInsts = append(out.StreamClusterInsts, outObj)
	}

	run.Mode = "streamcloudlet"
	for _, cloudlet := range in.Cloudlets {
		cloudletKeys := []edgeproto.CloudletKey{cloudlet.Key}
		outMsgs := [][]edgeproto.Result{}
		run.StreamObjApi_CloudletKey(&cloudletKeys, nil, &outMsgs)
		outObj := StreamCloudlet{Key: cloudlet.Key}
		for _, objsMsgs := range outMsgs {
			outObj.Msgs = objsMsgs
		}
		out.StreamCloudlets = append(out.StreamCloudlets, outObj)
	}
}
