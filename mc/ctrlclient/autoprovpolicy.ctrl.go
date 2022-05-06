// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoprovpolicy.proto

package ctrlclient

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	_ "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	_ "github.com/edgexr/edge-cloud/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	"io"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateAutoProvPolicyObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AutoProvPolicy, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewAutoProvPolicyApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.CreateAutoProvPolicy(ctx, obj)
}

func DeleteAutoProvPolicyObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AutoProvPolicy, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewAutoProvPolicyApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.DeleteAutoProvPolicy(ctx, obj)
}

func UpdateAutoProvPolicyObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AutoProvPolicy, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewAutoProvPolicyApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.UpdateAutoProvPolicy(ctx, obj)
}

func ShowAutoProvPolicyStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AutoProvPolicy, connObj ClientConnMgr, authz authzShow, cb func(res *edgeproto.AutoProvPolicy) error) error {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return err
	}
	api := edgeproto.NewAutoProvPolicyApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowAutoProvPolicy(ctx, obj)
	if err != nil {
		return err
	}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return err
		}
		if !rc.SkipAuthz {
			if authz != nil {
				if !authz.Ok(res.Key.Organization) {
					continue
				}
			}
		}
		err = cb(res)
		if err != nil {
			return err
		}
	}
	return nil
}

func AddAutoProvPolicyCloudletObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AutoProvPolicyCloudlet, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewAutoProvPolicyApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.AddAutoProvPolicyCloudlet(ctx, obj)
}

func RemoveAutoProvPolicyCloudletObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AutoProvPolicyCloudlet, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewAutoProvPolicyApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.RemoveAutoProvPolicyCloudlet(ctx, obj)
}
