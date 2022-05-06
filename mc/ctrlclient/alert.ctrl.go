// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

package ctrlclient

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/d-match-engine/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	"github.com/edgexr/edge-cloud-platform/log"
	"github.com/edgexr/edge-cloud-platform/mc/ormutil"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
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

type ShowAlertAuthz interface {
	Ok(obj *edgeproto.Alert) (bool, bool)
	Filter(obj *edgeproto.Alert)
}

func ShowAlertStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.Alert, connObj ClientConnMgr, authz ShowAlertAuthz, cb func(res *edgeproto.Alert) error) error {
	conn, err := connObj.GetRegionConn(ctx, rc.Region)
	if err != nil {
		return err
	}
	api := edgeproto.NewAlertApiClient(conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowAlert(ctx, obj)
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
