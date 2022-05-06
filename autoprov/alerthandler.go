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
	"context"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/opentracing/opentracing-go"
)

func alertChanged(ctx context.Context, old *edgeproto.Alert, new *edgeproto.Alert) {
	if new == nil {
		return
	}
	name, ok := new.Labels["alertname"]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "alertname not found", "alert", new)
		return
	}

	var handler func(ctx context.Context, name string, alert *edgeproto.Alert) error
	switch name {
	case cloudcommon.AlertClusterAutoScale:
		fallthrough
	case cloudcommon.AlertAutoScaleUp:
		fallthrough
	case cloudcommon.AlertAutoScaleDown:
		clusterAutoScaleWorkers.NeedsWork(ctx, new.GetKeyVal())
	case cloudcommon.AlertAutoUndeploy:
		handler = autoUndeploy
	}

	if handler == nil {
		return
	}
	// make a copy since we spawn a thread to deal with it.
	alert := alertCopy(new)
	go func() {
		cspan := log.StartSpan(log.DebugLevelApi, "handle alert", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
		log.SetTags(cspan, alert.GetKey().GetTags())
		cctx := log.ContextWithSpan(context.Background(), cspan)
		defer cspan.Finish()
		err := handler(cctx, name, alert)
		log.SpanLog(cctx, log.DebugLevelApi, "handled alert", "alert", alert, "err", err)
	}()
}

func alertCopy(a *edgeproto.Alert) *edgeproto.Alert {
	alert := *a
	for k, v := range a.Labels {
		alert.Labels[k] = v
	}
	for k, v := range a.Annotations {
		alert.Annotations[k] = v
	}
	return &alert
}

func autoUndeploy(ctx context.Context, name string, alert *edgeproto.Alert) error {
	if alert.State != "firing" {
		return nil
	}
	inst := edgeproto.AppInst{}
	inst.Key.AppKey.Organization = alert.Labels[edgeproto.AppKeyTagOrganization]
	inst.Key.AppKey.Name = alert.Labels[edgeproto.AppKeyTagName]
	inst.Key.AppKey.Version = alert.Labels[edgeproto.AppKeyTagVersion]
	inst.Key.ClusterInstKey.ClusterKey.Name = alert.Labels[edgeproto.ClusterKeyTagName]
	inst.Key.ClusterInstKey.Organization = alert.Labels[edgeproto.ClusterInstKeyTagOrganization]
	inst.Key.ClusterInstKey.CloudletKey.Name = alert.Labels[edgeproto.CloudletKeyTagName]
	inst.Key.ClusterInstKey.CloudletKey.Organization = alert.Labels[edgeproto.CloudletKeyTagOrganization]

	// we're already in a separate go thread so don't need another one here
	goAppInstApi(ctx, &inst, cloudcommon.Delete, cloudcommon.AutoProvReasonDemand, "")
	return nil
}
