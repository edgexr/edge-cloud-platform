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

package autoprov

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var testDialOpt grpc.DialOption

func goAppInstApi(ctx context.Context, inst *edgeproto.AppInst, action cloudcommon.Action, reason, policyName string) error {
	span := log.StartSpan(log.DebugLevelApi, "auto-prov deploy "+action.String(), opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
	log.SetTags(span, inst.GetTags())
	span.SetTag("reason", reason)
	defer span.Finish()
	ctx = log.ContextWithSpan(context.Background(), span)

	log.SpanLog(ctx, log.DebugLevelApi, "auto-prov deploy "+action.String(), "AppInst", inst.Key, "zone", inst.ZoneKey, "reason", reason, "policyName", policyName)
	if action != cloudcommon.Create && action != cloudcommon.Delete {
		log.SpanLog(ctx, log.DebugLevelApi, "invalid action", "action", action.String())
		return fmt.Errorf("invalid action")
	}
	eventStart := time.Now()
	eventName := "AutoProv create AppInst"
	if action == cloudcommon.Delete {
		eventName = "AutoProv delete AppInst"
	}

	err := runAppInstApi(ctx, inst, action, reason, policyName)
	log.SpanLog(ctx, log.DebugLevelApi, "auto-prov deploy result", "err", err)
	if err == nil {
		// Many calls fail because of checks done on the controller side.
		// These are not real failures. Only log an event if api call
		// was successful.
		nodeMgr.TimedEvent(ctx, eventName, inst.Key.Organization, svcnode.EventType, inst.GetTags(), err, eventStart, time.Now(), "reason", reason, "autoprovpolicy", policyName)
	}
	if reason == cloudcommon.AutoProvReasonMinMax {
		retryTracker.registerDeployResult(ctx, inst, err)
	}
	return err
}

func runAppInstApi(ctx context.Context, inst *edgeproto.AppInst, action cloudcommon.Action, reason, policyName string) error {
	opts := []grpc.DialOption{}
	if dialOpts != nil {
		opts = append(opts, dialOpts)
	}
	if testDialOpt != nil {
		opts = append(opts, testDialOpt)
	}
	opts = append(opts, grpc.WithBlock(),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})),
	)
	conn, err := grpc.Dial(*ctrlAddr, opts...)
	if err != nil {
		return err
	}
	defer conn.Close()

	kvPairs := []string{
		cloudcommon.CallerAutoProv, "",
		cloudcommon.AutoProvReason, reason,
		cloudcommon.AutoProvPolicyName, policyName}
	ctx = metadata.AppendToOutgoingContext(ctx, kvPairs...)
	client := edgeproto.NewAppInstApiClient(conn)
	var stream edgeproto.AppInstApi_CreateAppInstClient
	switch action {
	case cloudcommon.Create:
		inst.Liveness = edgeproto.Liveness_LIVENESS_AUTOPROV
		stream, err = client.CreateAppInst(ctx, inst)
	case cloudcommon.Delete:
		stream, err = client.DeleteAppInst(ctx, inst)
	}
	if err != nil {
		return err
	}
	for {
		_, err = stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
	}
	return err
}
