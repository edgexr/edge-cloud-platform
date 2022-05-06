// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: operatorcode.proto

package orm

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	"github.com/edgexr/edge-cloud-platform/log"
	"github.com/edgexr/edge-cloud-platform/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/mc/ormapi"
	"github.com/edgexr/edge-cloud-platform/mc/ormutil"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/labstack/echo"
	"google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func CreateOperatorCode(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionOperatorCode{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.OperatorCode.Organization)

	obj := &in.OperatorCode
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateOperatorCode(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Organization,
			ResourceCloudlets, ActionManage, withRequiresOrg(obj.Organization)); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.CreateOperatorCodeObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func DeleteOperatorCode(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionOperatorCode{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.OperatorCode.Organization)

	obj := &in.OperatorCode
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteOperatorCode(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Organization,
			ResourceCloudlets, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.DeleteOperatorCodeObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func ShowOperatorCode(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionOperatorCode{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	span.SetTag("org", in.OperatorCode.Organization)

	obj := &in.OperatorCode
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceCloudlets, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.OperatorCode) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowOperatorCodeStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}