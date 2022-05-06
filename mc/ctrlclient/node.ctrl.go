// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

package ctrlclient

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	_ "github.com/edgexr/edge-cloud/protogen"
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

func ShowNodeStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.Node, connObj ClientConnMgr, authz authzShow, cb func(res *edgeproto.Node) error) error {
	conn, err := connObj.GetNotifyRootConn(ctx)
	if err != nil {
		return err
	}
	api := edgeproto.NewNodeApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowNode(ctx, obj)
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
				if !authz.Ok("") {
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
