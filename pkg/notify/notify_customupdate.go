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

	dmeproto "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
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

func (s *AppSend) UpdateOk(ctx context.Context, app *edgeproto.App) bool {
	// Always send Apps to allow for App changes to reach cloudlet-filtered CRMs.
	// Otherwise, we would need to check every AppInst to see if it applies to
	// in the case of filterCloudletKeys.
	return true
}

func (s *AppInstSend) UpdateOk(ctx context.Context, appInst *edgeproto.AppInst) bool {
	triggerSend := false
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.cloudletReady {
			return false
		}
		if !s.sendrecv.hasCloudletKey(&appInst.CloudletKey) {
			return false
		}
		triggerSend = true
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if appInst.CloudletKey.FederatedOrganization == "" {
			return false
		}
		triggerSend = true
	}
	// also trigger sending app
	if triggerSend && s.sendrecv.appSend != nil {
		s.sendrecv.appSend.updateInternal(ctx, &appInst.AppKey, 0, NoForceDelete)
	}
	return true
}

func (s *CloudletSend) UpdateOk(ctx context.Context, cloudlet *edgeproto.Cloudlet) bool {
	triggerSend := false
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.hasCloudletKey(&cloudlet.Key) {
			return false
		}
		triggerSend = true
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if cloudlet.Key.FederatedOrganization == "" {
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
		if cloudlet.VmPool != "" {
			// also trigger send of vmpool object
			s.sendrecv.vmPoolSend.updateInternal(ctx, &edgeproto.VMPoolKey{
				Name:         cloudlet.VmPool,
				Organization: cloudlet.Key.Organization,
			}, 0, NoForceDelete)
		}
		if s.sendrecv.gpuDriverSend != nil && cloudlet.GpuConfig.Driver.Name != "" {
			// also trigger send of GPU driver object
			s.sendrecv.gpuDriverSend.updateInternal(ctx, &cloudlet.GpuConfig.Driver, 0, NoForceDelete)
		}
	}
	return true
}

func (s *ClusterInstSend) UpdateOk(ctx context.Context, clusterInst *edgeproto.ClusterInst) bool {
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.cloudletReady {
			return false
		}
		if !s.sendrecv.hasCloudletKey(&clusterInst.CloudletKey) {
			return false
		}
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if clusterInst.CloudletKey.FederatedOrganization == "" {
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
		if !s.sendrecv.hasCloudletKey(&msg.CloudletKey) {
			return false
		}
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if msg.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *VMPoolSend) UpdateOk(ctx context.Context, vmpool *edgeproto.VMPool) bool {
	if s.sendrecv.filterCloudletKeys {
		for cKey, _ := range s.sendrecv.cloudletKeys {
			cloudlet := edgeproto.Cloudlet{}
			var modRev int64
			if cKey.Organization != vmpool.Key.Organization {
				continue
			}
			if s.sendrecv.cloudletSend.handler.GetWithRev(&cKey, &cloudlet, &modRev) {
				if cloudlet.VmPool != vmpool.Key.Name {
					continue
				}
				return true
			}
		}
		return false
	}
	return true
}

func (s *GPUDriverSend) UpdateOk(ctx context.Context, gpuDriver *edgeproto.GPUDriver) bool {
	if s.sendrecv.filterCloudletKeys {
		for cKey, _ := range s.sendrecv.cloudletKeys {
			cloudlet := edgeproto.Cloudlet{}
			var modRev int64
			if s.sendrecv.cloudletSend.handler.GetWithRev(&cKey, &cloudlet, &modRev) {
				if cloudlet.GpuConfig.Driver.Matches(&gpuDriver.Key) {
					return true
				}
			}
		}
		return false
	}
	return true
}

func (s *TrustPolicyExceptionSend) UpdateOk(ctx context.Context, tpe *edgeproto.TrustPolicyException) bool {
	if s.sendrecv.filterCloudletKeys {
		for cKey, _ := range s.sendrecv.cloudletKeys {
			if cKey.Organization != tpe.Key.CloudletPoolKey.Organization {
				continue
			}
			return true
		}
		return false
	}
	return true
}

func (s *TPEInstanceStateSend) UpdateOk(ctx context.Context, tpe *edgeproto.TPEInstanceState) bool {
	if s.sendrecv.filterCloudletKeys {
		if !s.sendrecv.cloudletReady {
			return false
		}
		if !s.sendrecv.hasCloudletKey(&tpe.Key.CloudletKey) {
			return false
		}
	}
	if s.sendrecv.filterFederatedCloudlet {
		// Federated cloudlets are ignored by CRMs and are handled by FRMs
		if tpe.Key.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *AppSend) UpdateAllOkLocked(app *edgeproto.App) bool {
	return true
}

func (s *AppInstSend) UpdateAllOkLocked(appInst *edgeproto.AppInst) bool {
	if s.sendrecv.filterCloudletKeys {
		return false
	}
	if s.sendrecv.filterFederatedCloudlet {
		if appInst.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *CloudletSend) UpdateAllOkLocked(cloudlet *edgeproto.Cloudlet) bool {
	if s.sendrecv.filterCloudletKeys {
		return false
	}
	if s.sendrecv.filterFederatedCloudlet {
		if cloudlet.Key.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *ClusterInstSend) UpdateAllOkLocked(clusterInst *edgeproto.ClusterInst) bool {
	if s.sendrecv.filterCloudletKeys {
		return false
	}
	if s.sendrecv.filterFederatedCloudlet {
		if clusterInst.CloudletKey.FederatedOrganization == "" {
			return false
		}
	}
	return true
}

func (s *VMPoolSend) UpdateAllOkLocked(vmpool *edgeproto.VMPool) bool {
	return !s.sendrecv.filterCloudletKeys
}

func (s *GPUDriverSend) UpdateAllOkLocked(gpuDriver *edgeproto.GPUDriver) bool {
	return !s.sendrecv.filterCloudletKeys
}

func (s *TrustPolicyExceptionSend) UpdateAllOkLocked(tpe *edgeproto.TrustPolicyException) bool {
	return !s.sendrecv.filterCloudletKeys
}

func (s *TPEInstanceStateSend) UpdateAllOkLocked(tpe *edgeproto.TPEInstanceState) bool {
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
				s.sendrecv.cloudletSend.Update(ctx, &cloudlet, 0)
			}
		}
		if buf.State == dmeproto.CloudletState_CLOUDLET_STATE_READY || buf.State == dmeproto.CloudletState_CLOUDLET_STATE_NEED_SYNC && !buf.ControllerCacheReceived {
			log.SpanLog(ctx, log.DebugLevelNotify, "CloudletInfo recv hook read, send all filtered data", "key", buf.Key)
			// allow all filtered objects to be sent
			s.sendrecv.cloudletReady = true

			// trigger send of all objects related to cloudlet
			// In case of cloudlet upgrade, Check if READY is
			// received from the appropriate cloudlet
			if !s.sendrecv.cloudletSend.handler.GetWithRev(&buf.Key, &cloudlet, &modRev) {
				log.SpanLog(ctx, log.DebugLevelNotify, "Lookup of cloudlet failed", "key", buf.Key)
			} else {
				if buf.ContainerVersion != "" && s.sendrecv.cloudletSend != nil {
					if s.sendrecv.cloudletSend.handler.GetWithRev(&buf.Key, &cloudlet, &modRev) &&
						(cloudlet.State == edgeproto.TrackedState_UPDATE_REQUESTED ||
							cloudlet.State == edgeproto.TrackedState_UPDATING) &&
						cloudlet.ContainerVersion != buf.ContainerVersion {
						return
					}
				}
				// After cloudlet upgrade, when CLOUDLET_STATE_READY state
				// is seen from upgraded CRM, then following will trigger
				// send of all objects (which includes objects missed
				// during upgrade)
				s.sendrecv.sendForCloudlet(ctx, notice.Action, &cloudlet)
				s.sendrecv.triggerSendAllEnd()
			}
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
