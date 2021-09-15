// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: device.proto

package orm

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	"google.golang.org/grpc/status"
	"io"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func InjectDevice(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionDevice{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.Device.GetKey().GetTags())
	resp, err := InjectDeviceObj(ctx, rc, &in.Device)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func InjectDeviceObj(ctx context.Context, rc *RegionContext, obj *edgeproto.Device) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForInjectDevice(); err != nil {
		return nil, err
	}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, "",
			ResourceConfig, ActionManage); err != nil {
			return nil, err
		}
	}
	if rc.conn == nil {
		conn, err := connCache.GetRegionConn(ctx, rc.region)
		if err != nil {
			return nil, err
		}
		rc.conn = conn
		defer func() {
			rc.conn = nil
		}()
	}
	api := edgeproto.NewDeviceApiClient(rc.conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.InjectDevice(ctx, obj)
}

func ShowDevice(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionDevice{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.Device.GetKey().GetTags())

	err = ShowDeviceStream(ctx, rc, &in.Device, func(res *edgeproto.Device) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}

func ShowDeviceStream(ctx context.Context, rc *RegionContext, obj *edgeproto.Device, cb func(res *edgeproto.Device) error) error {
	var authz *AuthzShow
	var err error
	if !rc.skipAuthz {
		authz, err = newShowAuthz(ctx, rc.region, rc.username, ResourceConfig, ActionView)
		if err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connCache.GetRegionConn(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn = nil
		}()
	}
	api := edgeproto.NewDeviceApiClient(rc.conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowDevice(ctx, obj)
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
		if !rc.skipAuthz {
			if !authz.Ok("") {
				continue
			}
		}
		err = cb(res)
		if err != nil {
			return err
		}
	}
	return nil
}

func ShowDeviceObj(ctx context.Context, rc *RegionContext, obj *edgeproto.Device) ([]edgeproto.Device, error) {
	arr := []edgeproto.Device{}
	err := ShowDeviceStream(ctx, rc, obj, func(res *edgeproto.Device) error {
		arr = append(arr, *res)
		return nil
	})
	return arr, err
}

func EvictDevice(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionDevice{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.Device.GetKey().GetTags())
	resp, err := EvictDeviceObj(ctx, rc, &in.Device)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func EvictDeviceObj(ctx context.Context, rc *RegionContext, obj *edgeproto.Device) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForEvictDevice(); err != nil {
		return nil, err
	}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, "",
			ResourceConfig, ActionManage); err != nil {
			return nil, err
		}
	}
	if rc.conn == nil {
		conn, err := connCache.GetRegionConn(ctx, rc.region)
		if err != nil {
			return nil, err
		}
		rc.conn = conn
		defer func() {
			rc.conn = nil
		}()
	}
	api := edgeproto.NewDeviceApiClient(rc.conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	return api.EvictDevice(ctx, obj)
}

func ShowDeviceReport(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionDeviceReport{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.DeviceReport.GetKey().GetTags())

	err = ShowDeviceReportStream(ctx, rc, &in.DeviceReport, func(res *edgeproto.Device) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}

func ShowDeviceReportStream(ctx context.Context, rc *RegionContext, obj *edgeproto.DeviceReport, cb func(res *edgeproto.Device) error) error {
	var authz *AuthzShow
	var err error
	if !rc.skipAuthz {
		authz, err = newShowAuthz(ctx, rc.region, rc.username, ResourceConfig, ActionView)
		if err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connCache.GetRegionConn(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn = nil
		}()
	}
	api := edgeproto.NewDeviceApiClient(rc.conn)
	log.SpanLog(ctx, log.DebugLevelApi, "start controller api")
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish controller api")
	stream, err := api.ShowDeviceReport(ctx, obj)
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
		if !rc.skipAuthz {
			if !authz.Ok("") {
				continue
			}
		}
		err = cb(res)
		if err != nil {
			return err
		}
	}
	return nil
}

func ShowDeviceReportObj(ctx context.Context, rc *RegionContext, obj *edgeproto.DeviceReport) ([]edgeproto.Device, error) {
	arr := []edgeproto.Device{}
	err := ShowDeviceReportStream(ctx, rc, obj, func(res *edgeproto.Device) error {
		arr = append(arr, *res)
		return nil
	})
	return arr, err
}
