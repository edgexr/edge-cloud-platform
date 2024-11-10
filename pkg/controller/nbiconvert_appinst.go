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

package controller

import (
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
)

func (s *NBIAPI) NBIAppInst(in *edgeproto.AppInst) (*nbi.AppInstanceInfo, error) {
	ai := nbi.AppInstanceInfo{}
	ai.Name = in.Key.Name
	ai.AppProvider = in.Key.Organization
	ai.AppInstanceId = in.ObjId
	// Lookup app ID.
	app := edgeproto.App{}
	if s.allApis.appApi.cache.Get(&in.AppKey, &app) {
		ai.AppId = app.ObjId
	}
	// Lookup zone ID. Note that zone may not be set if cloudlet
	// was removed from zone.
	zone := edgeproto.Zone{}
	if s.allApis.zoneApi.cache.Get(&in.ZoneKey, &zone) {
		ai.EdgeCloudZoneId = zone.ObjId
	}
	endpoints := []nbi.AppInstanceInfo_ComponentEndpointInfo{}
	for _, port := range in.MappedPorts {
		// XXX: does FqdnPrefix append or prepend?
		fqdn := in.Uri + port.FqdnPrefix
		endpoint := nbi.AppInstanceInfo_ComponentEndpointInfo{
			InterfaceId: port.Id,
			AccessPoints: nbi.AccessEndpoint{
				Fqdn: &fqdn,
				Port: int(port.PublicPort),
			},
		}
		endpoints = append(endpoints, endpoint)
	}
	ai.ComponentEndpointInfo = &endpoints

	if in.ClusterKey.Name != "" {
		// Note: VM instances do not have clusters
		cluster := edgeproto.ClusterInst{}
		if s.allApis.clusterInstApi.cache.Get(&in.ClusterKey, &cluster) {
			ai.KubernetesClusterRef = &cluster.ObjId
		}
	}
	if in.State == edgeproto.TrackedState_CREATE_REQUESTED ||
		in.State == edgeproto.TrackedState_CREATING_DEPENDENCIES ||
		in.State == edgeproto.TrackedState_CREATING ||
		in.State == edgeproto.TrackedState_UPDATE_REQUESTED ||
		in.State == edgeproto.TrackedState_UPDATING {
		ai.Status = toPtr(nbi.AppInstanceInfoStatusInstantiating)
	} else if in.State == edgeproto.TrackedState_DELETE_REQUESTED ||
		in.State == edgeproto.TrackedState_DELETE_PREPARE ||
		in.State == edgeproto.TrackedState_DELETING {
		ai.Status = toPtr(nbi.AppInstanceInfoStatusTerminating)
	} else if in.State == edgeproto.TrackedState_READY {
		ai.Status = toPtr(nbi.AppInstanceInfoStatusReady)
	} else if in.State == edgeproto.TrackedState_CREATE_ERROR ||
		in.State == edgeproto.TrackedState_UPDATE_ERROR ||
		in.State == edgeproto.TrackedState_DELETE_ERROR {
		ai.Status = toPtr(nbi.AppInstanceInfoStatusFailed)
	} else {
		ai.Status = toPtr(nbi.AppInstanceInfoStatusUnknown)
	}
	return &ai, nil
}

func toPtr[T any](v T) *T {
	return &v
}

func NBIAppInstSort(a, b nbi.AppInstanceInfo) int {
	akey := a.Name + a.AppProvider
	bkey := b.Name + b.AppProvider
	return strings.Compare(akey, bkey)
}
