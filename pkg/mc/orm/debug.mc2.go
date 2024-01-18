// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

package orm

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/labstack/echo/v4"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func EnableDebugLevels(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionDebugRequest{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)

	obj := &in.DebugRequest
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForEnableDebugLevels(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.DebugReply) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.EnableDebugLevelsStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func DisableDebugLevels(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionDebugRequest{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)

	obj := &in.DebugRequest
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDisableDebugLevels(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.DebugReply) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.DisableDebugLevelsStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func ShowDebugLevels(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionDebugRequest{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)

	obj := &in.DebugRequest
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionView); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.DebugReply) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowDebugLevelsStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func RunDebug(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionDebugRequest{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)

	obj := &in.DebugRequest
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRunDebug(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.DebugReply) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.RunDebugStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}
