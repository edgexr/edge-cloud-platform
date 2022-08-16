// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinst.proto

package orm

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/labstack/echo/v4"
	"google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInst{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	obj := &in.AppInst
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateAppInst(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzCreateAppInst(ctx, rc.Region, rc.Username, obj,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	// Need access to database for federation handling
	rc.Database = database

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.CreateAppInstStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func DeleteAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInst{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	obj := &in.AppInst
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteAppInst(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	// Need access to database for federation handling
	rc.Database = database

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.DeleteAppInstStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func RefreshAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInst{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	obj := &in.AppInst
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRefreshAppInst(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	// Need access to database for federation handling
	rc.Database = database

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.RefreshAppInstStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func UpdateAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInst{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.AppInst
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateAppInst(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}
	// Need access to database for federation handling
	rc.Database = database

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.UpdateAppInstStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func ShowAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInst{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInst.GetKey().GetTags())
	span.SetTag("org", in.AppInst.Key.AppKey.Organization)

	obj := &in.AppInst
	var authz ctrlclient.ShowAppInstAuthz
	if !rc.SkipAuthz {
		authz, err = newShowAppInstAuthz(ctx, rc.Region, rc.Username, ResourceAppInsts, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.AppInst) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowAppInstStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}

func RequestAppInstLatency(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInstLatency{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AppInstLatency.GetKey().GetTags())
	span.SetTag("org", in.AppInstLatency.Key.AppKey.Organization)

	obj := &in.AppInstLatency
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRequestAppInstLatency(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.AppKey.Organization,
			ResourceAppInsts, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.RequestAppInstLatencyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}
