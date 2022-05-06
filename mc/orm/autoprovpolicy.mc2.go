// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoprovpolicy.proto

package orm

import (
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	_ "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	_ "github.com/edgexr/edge-cloud/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	"github.com/labstack/echo"
	"google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateAutoProvPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAutoProvPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AutoProvPolicy.GetKey().GetTags())
	span.SetTag("org", in.AutoProvPolicy.Key.Organization)

	obj := &in.AutoProvPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateAutoProvPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzCreateAutoProvPolicy(ctx, rc.Region, rc.Username, obj,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.CreateAutoProvPolicyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func DeleteAutoProvPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAutoProvPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AutoProvPolicy.GetKey().GetTags())
	span.SetTag("org", in.AutoProvPolicy.Key.Organization)

	obj := &in.AutoProvPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteAutoProvPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.DeleteAutoProvPolicyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func UpdateAutoProvPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAutoProvPolicy{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AutoProvPolicy.GetKey().GetTags())
	span.SetTag("org", in.AutoProvPolicy.Key.Organization)
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.AutoProvPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateAutoProvPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzUpdateAutoProvPolicy(ctx, rc.Region, rc.Username, obj,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.UpdateAutoProvPolicyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func ShowAutoProvPolicy(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAutoProvPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AutoProvPolicy.GetKey().GetTags())
	span.SetTag("org", in.AutoProvPolicy.Key.Organization)

	obj := &in.AutoProvPolicy
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceDeveloperPolicy, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.AutoProvPolicy) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowAutoProvPolicyStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}

func AddAutoProvPolicyCloudlet(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAutoProvPolicyCloudlet{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AutoProvPolicyCloudlet.GetKey().GetTags())
	span.SetTag("org", in.AutoProvPolicyCloudlet.Key.Organization)

	obj := &in.AutoProvPolicyCloudlet
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForAddAutoProvPolicyCloudlet(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzAddAutoProvPolicyCloudlet(ctx, rc.Region, rc.Username, obj,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.AddAutoProvPolicyCloudletObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func RemoveAutoProvPolicyCloudlet(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAutoProvPolicyCloudlet{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AutoProvPolicyCloudlet.GetKey().GetTags())
	span.SetTag("org", in.AutoProvPolicyCloudlet.Key.Organization)

	obj := &in.AutoProvPolicyCloudlet
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRemoveAutoProvPolicyCloudlet(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.RemoveAutoProvPolicyCloudletObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}
