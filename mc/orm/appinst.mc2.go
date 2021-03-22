// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinst.proto

package orm

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	_ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
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

func CreateAppInst(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAppInst{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	err = CreateAppInstStream(ctx, rc, &in.AppInst, func(res *edgeproto.Result) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

func CreateAppInstStream(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst, cb func(res *edgeproto.Result)) error {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateAppInst(); err != nil {
		return err
	}
	if !rc.skipAuthz {
		if err := authzCreateAppInst(ctx, rc.region, rc.username, obj,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAppInstApiClient(rc.conn)
	stream, err := api.CreateAppInst(ctx, obj)
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
		cb(res)
	}
	return nil
}

func CreateAppInstObj(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst) ([]edgeproto.Result, error) {
	arr := []edgeproto.Result{}
	err := CreateAppInstStream(ctx, rc, obj, func(res *edgeproto.Result) {
		arr = append(arr, *res)
	})
	return arr, err
}

func DeleteAppInst(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAppInst{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	err = DeleteAppInstStream(ctx, rc, &in.AppInst, func(res *edgeproto.Result) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

func DeleteAppInstStream(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst, cb func(res *edgeproto.Result)) error {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteAppInst(); err != nil {
		return err
	}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAppInstApiClient(rc.conn)
	stream, err := api.DeleteAppInst(ctx, obj)
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
		cb(res)
	}
	return nil
}

func DeleteAppInstObj(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst) ([]edgeproto.Result, error) {
	arr := []edgeproto.Result{}
	err := DeleteAppInstStream(ctx, rc, obj, func(res *edgeproto.Result) {
		arr = append(arr, *res)
	})
	return arr, err
}

func RefreshAppInst(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAppInst{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	err = RefreshAppInstStream(ctx, rc, &in.AppInst, func(res *edgeproto.Result) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

func RefreshAppInstStream(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst, cb func(res *edgeproto.Result)) error {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRefreshAppInst(); err != nil {
		return err
	}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAppInstApiClient(rc.conn)
	stream, err := api.RefreshAppInst(ctx, obj)
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
		cb(res)
	}
	return nil
}

func RefreshAppInstObj(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst) ([]edgeproto.Result, error) {
	arr := []edgeproto.Result{}
	err := RefreshAppInstStream(ctx, rc, obj, func(res *edgeproto.Result) {
		arr = append(arr, *res)
	})
	return arr, err
}

func UpdateAppInst(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAppInst{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	err = UpdateAppInstStream(ctx, rc, &in.AppInst, func(res *edgeproto.Result) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

func UpdateAppInstStream(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst, cb func(res *edgeproto.Result)) error {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateAppInst(); err != nil {
		return err
	}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAppInstApiClient(rc.conn)
	stream, err := api.UpdateAppInst(ctx, obj)
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
		cb(res)
	}
	return nil
}

func UpdateAppInstObj(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst) ([]edgeproto.Result, error) {
	arr := []edgeproto.Result{}
	err := UpdateAppInstStream(ctx, rc, obj, func(res *edgeproto.Result) {
		arr = append(arr, *res)
	})
	return arr, err
}

func ShowAppInst(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAppInst{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	err = ShowAppInstStream(ctx, rc, &in.AppInst, func(res *edgeproto.AppInst) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

func ShowAppInstStream(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst, cb func(res *edgeproto.AppInst)) error {
	var authz *AuthzShow
	var err error
	if !rc.skipAuthz {
		authz, err = newShowAuthz(ctx, rc.region, rc.username, ResourceAppInsts, ActionView)
		if err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAppInstApiClient(rc.conn)
	stream, err := api.ShowAppInst(ctx, obj)
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
			if !authz.Ok(res.Key.AppKey.Organization) {
				continue
			}
		}
		cb(res)
	}
	return nil
}

func ShowAppInstObj(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInst) ([]edgeproto.AppInst, error) {
	arr := []edgeproto.AppInst{}
	err := ShowAppInstStream(ctx, rc, obj, func(res *edgeproto.AppInst) {
		arr = append(arr, *res)
	})
	return arr, err
}

func RequestAppInstLatency(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAppInstLatency{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInstLatency.GetKey().GetTags())
	span.SetTag("org", in.AppInstLatency.Key.AppKey.Organization)
	resp, err := RequestAppInstLatencyObj(ctx, rc, &in.AppInstLatency)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func RequestAppInstLatencyObj(ctx context.Context, rc *RegionContext, obj *edgeproto.AppInstLatency) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRequestAppInstLatency(); err != nil {
		return nil, err
	}
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return nil, err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return nil, err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAppInstLatencyApiClient(rc.conn)
	return api.RequestAppInstLatency(ctx, obj)
}
