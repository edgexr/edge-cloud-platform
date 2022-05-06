// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicyexception.proto

package ctrlclient

import (
	"context"
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"io"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateTrustPolicyExceptionObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.TrustPolicyException, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewTrustPolicyExceptionApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.CreateTrustPolicyException(ctx, obj)
}

func UpdateTrustPolicyExceptionObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.TrustPolicyException, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewTrustPolicyExceptionApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.UpdateTrustPolicyException(ctx, obj)
}

func DeleteTrustPolicyExceptionObj(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.TrustPolicyException, connObj ClientConnMgr) (*edgeproto.Result, error) {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewTrustPolicyExceptionApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.DeleteTrustPolicyException(ctx, obj)
}

type ShowTrustPolicyExceptionAuthz interface {
	Ok(obj *edgeproto.TrustPolicyException) (bool, bool)
	Filter(obj *edgeproto.TrustPolicyException)
}

func ShowTrustPolicyExceptionStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.TrustPolicyException, connObj ClientConnMgr, authz ShowTrustPolicyExceptionAuthz, cb func(res *edgeproto.TrustPolicyException) error) error {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return err
	}
	api := edgeproto.NewTrustPolicyExceptionApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowTrustPolicyException(ctx, obj)
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
				authzOk, filterOutput := authz.Ok(res)
				if !authzOk {
					continue
				}
				if filterOutput {
					authz.Filter(res)
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
