// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alertpolicy.proto

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
	"google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateAlertPolicy(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAlertPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AlertPolicy.GetKey().GetTags())
	span.SetTag("org", in.AlertPolicy.Key.Organization)

	obj := &in.AlertPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateAlertPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceDeveloperPolicy, ActionManage, withRequiresOrg(obj.Key.Organization)); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.CreateAlertPolicyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func DeleteAlertPolicy(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAlertPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AlertPolicy.GetKey().GetTags())
	span.SetTag("org", in.AlertPolicy.Key.Organization)

	obj := &in.AlertPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteAlertPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.DeleteAlertPolicyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func UpdateAlertPolicy(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAlertPolicy{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AlertPolicy.GetKey().GetTags())
	span.SetTag("org", in.AlertPolicy.Key.Organization)
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.AlertPolicy
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateAlertPolicy(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceDeveloperPolicy, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.UpdateAlertPolicyObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func ShowAlertPolicy(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionAlertPolicy{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.AlertPolicy.GetKey().GetTags())
	span.SetTag("org", in.AlertPolicy.Key.Organization)

	obj := &in.AlertPolicy
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceDeveloperPolicy, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.AlertPolicy) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowAlertPolicyStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}
