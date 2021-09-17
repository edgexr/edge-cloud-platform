// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: stream.proto

package orm

import (
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ctrlapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func StreamAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAppInstKey{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.AppInstKey.AppKey.Organization)

	obj := &in.AppInstKey
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.AppKey.Organization,
			ResourceAppInsts, ActionView); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlapi.StreamAppInstStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func StreamClusterInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionClusterInstKey{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.ClusterInstKey.Organization)

	obj := &in.ClusterInstKey
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Organization,
			ResourceClusterInsts, ActionView); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlapi.StreamClusterInstStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func StreamCloudlet(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletKey{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.CloudletKey.Organization)

	obj := &in.CloudletKey
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Organization,
			ResourceCloudlets, ActionView); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlapi.StreamCloudletStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func StreamGPUDriver(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionGPUDriverKey{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.GPUDriverKey.Organization)

	obj := &in.GPUDriverKey
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Organization,
			ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlapi.StreamGPUDriverStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}
