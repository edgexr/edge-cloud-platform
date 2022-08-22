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

package notify

import (
	"context"

	dmeproto "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

var NoForceDelete = false

// Customize functions are used to filter sending of data
// to the CRM by sending only objects related to the CloudletKey.
// The remote initially tells us it wants cloudletKey filtering.
// If so, none of the below objects are sent until we receive a
// cloudletkey via CloudletInfo. Then further updates (sends) are
// filtered by cloudletkey(s).

func (s *AppSend) UpdateOk(ctx context.Context, key *edgeproto.AppKey) bool {
	// Always send Apps to allow for App changes to reach cloudlet-filtered CRMs.
	// Otherwise, we would need to check every AppInst to see if it applies to
	// in the case of filterCloudletKeys.
	return true
}

func (s *AppInstSend) UpdateOk(ctx context.Context, key *edgeproto.AppInstKey) bool {
	triggerSend := false
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.cloudletReady {
			return false
		}
		if !s.sendrecv.hasCloudletKey(&key.ClusterInstKey.CloudletKey) {
			return false
		}
		triggerSend = true
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if key.ClusterInstKey.CloudletKey.FederatedOrganization == "" {
			return false
		}
		triggerSend = true
	}
	// also trigger sending app
	if triggerSend && s.sendrecv.appSend != nil {
		s.sendrecv.appSend.updateInternal(ctx, &key.AppKey, 0, NoForceDelete)
	}
	return true
}

func (s *CloudletSend) UpdateOk(ctx context.Context, key *edgeproto.CloudletKey) bool {
	triggerSend := false
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.hasCloudletKey(key) {
			return false
		}
		triggerSend = true
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if key.FederatedOrganization == "" {
			return false
		}
		// trigger send of VMPool and GPUDrivers is not needed because they
		// are always sent regardless of filterFederatedCloudlet.
	}
	if triggerSend {
		// For filterCloudletKeys, we need to send referenced VMPools and
		// GPUDrivers if cloudlet now refers to a new one that was never
		// sent before.
		cloudlet := edgeproto.Cloudlet{}
		var modRev int64
		if s.handler.GetWithRev(key, &cloudlet, &modRev) {
			if cloudlet.VmPool != "" {
				// also trigger send of vmpool object
				s.sendrecv.vmPoolSend.updateInternal(ctx, &edgeproto.VMPoolKey{
					Name:         cloudlet.VmPool,
					Organization: key.Organization,
				}, 0, NoForceDelete)
			}
			if s.sendrecv.gpuDriverSend != nil && cloudlet.GpuConfig.Driver.Name != "" {
				// also trigger send of GPU driver object
				s.sendrecv.gpuDriverSend.updateInternal(ctx, &cloudlet.GpuConfig.Driver, 0, NoForceDelete)
			}
		}
	}
	return true
}

func (s *ClusterInstSend) UpdateOk(ctx context.Context, key *edgeproto.ClusterInstKey) bool {
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.cloudletReady {
			return false
		}
		if !s.sendrecv.hasCloudletKey(&key.CloudletKey) {
			return false
		}
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if key.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *ExecRequestSend) UpdateOk(ctx context.Context, msg *edgeproto.ExecRequest) bool {
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.cloudletReady {
			return false
		}
		if !s.sendrecv.hasCloudletKey(&msg.AppInstKey.ClusterInstKey.CloudletKey) {
			return false
		}
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if msg.AppInstKey.ClusterInstKey.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *VMPoolSend) UpdateOk(ctx context.Context, key *edgeproto.VMPoolKey) bool {
	if s.sendrecv.filterCloudletKeys {
		for cKey, _ := range s.sendrecv.cloudletKeys {
			cloudlet := edgeproto.Cloudlet{}
			var modRev int64
			if cKey.Organization != key.Organization {
				continue
			}
			if s.sendrecv.cloudletSend.handler.GetWithRev(&cKey, &cloudlet, &modRev) {
				if cloudlet.VmPool != key.Name {
					continue
				}
				return true
			}
		}
		return false
	}
	return true
}

func (s *GPUDriverSend) UpdateOk(ctx context.Context, key *edgeproto.GPUDriverKey) bool {
	if s.sendrecv.filterCloudletKeys {
		for cKey, _ := range s.sendrecv.cloudletKeys {
			cloudlet := edgeproto.Cloudlet{}
			var modRev int64
			if s.sendrecv.cloudletSend.handler.GetWithRev(&cKey, &cloudlet, &modRev) {
				if cloudlet.GpuConfig.Driver.Matches(key) {
					return true
				}
			}
		}
		return false
	}
	return true
}

func (s *TrustPolicyExceptionSend) UpdateOk(ctx context.Context, key *edgeproto.TrustPolicyExceptionKey) bool {
	if s.sendrecv.filterCloudletKeys {
		for cKey, _ := range s.sendrecv.cloudletKeys {
			if cKey.Organization != key.CloudletPoolKey.Organization {
				continue
			}
			return true
		}
		return false
	}
	return true
}

func (s *AppSend) UpdateAllOkLocked(key *edgeproto.AppKey) bool {
	return true
}

func (s *AppInstSend) UpdateAllOkLocked(key *edgeproto.AppInstKey) bool {
	if s.sendrecv.filterCloudletKeys {
		return false
	}
	if s.sendrecv.filterFederatedCloudlet {
		if key.ClusterInstKey.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *CloudletSend) UpdateAllOkLocked(key *edgeproto.CloudletKey) bool {
	if s.sendrecv.filterCloudletKeys {
		return false
	}
	if s.sendrecv.filterFederatedCloudlet {
		if key.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *ClusterInstSend) UpdateAllOkLocked(key *edgeproto.ClusterInstKey) bool {
	if s.sendrecv.filterCloudletKeys {
		return false
	}
	if s.sendrecv.filterFederatedCloudlet {
		if key.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *VMPoolSend) UpdateAllOkLocked(key *edgeproto.VMPoolKey) bool {
	return !s.sendrecv.filterCloudletKeys
}

func (s *GPUDriverSend) UpdateAllOkLocked(key *edgeproto.GPUDriverKey) bool {
	return !s.sendrecv.filterCloudletKeys
}

func (s *TrustPolicyExceptionSend) UpdateAllOkLocked(key *edgeproto.TrustPolicyExceptionKey) bool {
	return !s.sendrecv.filterCloudletKeys
}

func (s *CloudletInfoRecv) RecvHook(ctx context.Context, notice *edgeproto.Notice, buf *edgeproto.CloudletInfo, peerAddr string) {
	log.SpanLog(ctx, log.DebugLevelNotify, "CloudletInfo RecvHook", "key", buf.Key, "state", buf.State)

	if !s.sendrecv.filterCloudletKeys {
		return
	}

	// set filter to allow sending of cloudlet data
	s.sendrecv.updateCloudletKey(notice.Action, &buf.Key)

	cloudlet := edgeproto.Cloudlet{
		Key: buf.Key,
	}
	var modRev int64

	if notice.Action == edgeproto.NoticeAction_UPDATE {
		if buf.State == dmeproto.CloudletState_CLOUDLET_STATE_READY ||
			buf.State == dmeproto.CloudletState_CLOUDLET_STATE_UPGRADE ||
			buf.State == dmeproto.CloudletState_CLOUDLET_STATE_NEED_SYNC ||
			buf.State == dmeproto.CloudletState_CLOUDLET_STATE_INIT {
			// trigger send of cloudlet details to cloudlet
			if s.sendrecv.cloudletSend != nil {
				log.SpanLog(ctx, log.DebugLevelNotify, "CloudletInfo recv hook, send Cloudlet update", "key", buf.Key, "state", buf.State)
				s.sendrecv.cloudletSend.Update(ctx, &buf.Key, nil, 0)
			}
		}
		if buf.State == dmeproto.CloudletState_CLOUDLET_STATE_READY || buf.State == dmeproto.CloudletState_CLOUDLET_STATE_NEED_SYNC && !buf.ControllerCacheReceived {
			log.SpanLog(ctx, log.DebugLevelNotify, "CloudletInfo recv hook read, send all filtered data", "key", buf.Key)
			// allow all filtered objects to be sent
			s.sendrecv.cloudletReady = true

			// trigger send of all objects related to cloudlet
			// In case of cloudlet upgrade, Check if READY is
			// received from the appropriate cloudlet
			if buf.ContainerVersion != "" && s.sendrecv.cloudletSend != nil {
				if s.sendrecv.cloudletSend.handler.GetWithRev(&buf.Key, &cloudlet, &modRev) &&
					(cloudlet.State == edgeproto.TrackedState_UPDATE_REQUESTED ||
						cloudlet.State == edgeproto.TrackedState_UPDATING) &&
					cloudlet.ContainerVersion != buf.ContainerVersion {
					return
				}
			}

			// Post cloudlet upgrade, when CLOUDLET_STATE_READY state
			// is seen from upgraded CRM, then following will trigger
			// send of all objects (which includes objects missed
			// during upgrade)
			s.sendrecv.sendForCloudlet(ctx, notice.Action, &cloudlet)
			s.sendrecv.triggerSendAllEnd()
		}
	}
	if notice.Action == edgeproto.NoticeAction_DELETE {
		// send deletes for all cloudlet-key related objects
		log.SpanLog(ctx, log.DebugLevelNotify, "CloudletInfo recv hook, send Cloudlet delete", "key", buf.Key)
		if s.sendrecv.cloudletSend != nil {
			s.sendrecv.cloudletSend.ForceDelete(ctx, &buf.Key, 0)
		}
		s.sendrecv.cloudletSend.handler.GetWithRev(&buf.Key, &cloudlet, &modRev)
		s.sendrecv.sendForCloudlet(ctx, notice.Action, &cloudlet)
	}
}

func (s *CloudletRecv) RecvHook(ctx context.Context, notice *edgeproto.Notice, buf *edgeproto.Cloudlet, perrAddr string) {
	// register cloudlet key on sendrecv for CRM, otherwise the
	// ExecRequest messages it tries to send back to the controller
	// will get filtered by UpdateOk above.
	s.sendrecv.updateCloudletKey(notice.Action, &buf.Key)
	s.sendrecv.cloudletReady = true
}
