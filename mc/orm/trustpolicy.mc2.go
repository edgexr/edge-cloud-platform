// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicy.proto

package orm

import (
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	_ "github.com/edgexr/edge-cloud/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/labstack/echo"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateTrustPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionTrustPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.TrustPolicy.GetKey().GetTags())
	span.SetTag("org", in.TrustPolicy.Key.Organization)

	obj := &in.TrustPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateTrustPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceCloudlets, ActionManage, withRequiresOrg(obj.Key.Organization)); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.CreateTrustPolicyStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func DeleteTrustPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionTrustPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.TrustPolicy.GetKey().GetTags())
	span.SetTag("org", in.TrustPolicy.Key.Organization)

	obj := &in.TrustPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteTrustPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceCloudlets, ActionManage); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.DeleteTrustPolicyStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func UpdateTrustPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionTrustPolicy{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.TrustPolicy.GetKey().GetTags())
	span.SetTag("org", in.TrustPolicy.Key.Organization)
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.TrustPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateTrustPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceCloudlets, ActionManage); err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.Result) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.UpdateTrustPolicyStream(ctx, rc, obj, connCache, cb)
	if err != nil {
		return err
	}
	return nil
}

func ShowTrustPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionTrustPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.TrustPolicy.GetKey().GetTags())
	span.SetTag("org", in.TrustPolicy.Key.Organization)

	obj := &in.TrustPolicy
	var authz ctrlclient.ShowTrustPolicyAuthz
	if !rc.SkipAuthz {
		authz, err = newShowTrustPolicyAuthz(ctx, rc.Region, rc.Username, ResourceCloudlets, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.TrustPolicy) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowTrustPolicyStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}
