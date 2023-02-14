// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: refs.proto

package ctrlclient

import (
	"context"
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
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

func ShowCloudletRefsStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.CloudletRefs, connObj ClientConnMgr, authz authzShow, cb func(res *edgeproto.CloudletRefs) error) error {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return err
	}
	api := edgeproto.NewCloudletRefsApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowCloudletRefs(ctx, obj)
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

func ShowClusterRefsStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.ClusterRefs, connObj ClientConnMgr, authz authzShow, cb func(res *edgeproto.ClusterRefs) error) error {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return err
	}
	api := edgeproto.NewClusterRefsApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowClusterRefs(ctx, obj)
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

func ShowAppInstRefsStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.AppInstRefs, connObj ClientConnMgr, authz authzShow, cb func(res *edgeproto.AppInstRefs) error) error {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return err
	}
	api := edgeproto.NewAppInstRefsApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowAppInstRefs(ctx, obj)
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