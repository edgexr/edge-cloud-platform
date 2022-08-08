// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudletpool.proto

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

func CreateCloudletPool(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletPool{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.CloudletPool.GetKey().GetTags())
	span.SetTag("org", in.CloudletPool.Key.Organization)

	obj := &in.CloudletPool
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateCloudletPool(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzCreateCloudletPool(ctx, rc.Region, rc.Username, obj,
			ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.CreateCloudletPoolObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func DeleteCloudletPool(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletPool{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.CloudletPool.GetKey().GetTags())
	span.SetTag("org", in.CloudletPool.Key.Organization)

	obj := &in.CloudletPool
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteCloudletPool(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzDeleteCloudletPool(ctx, rc.Region, rc.Username, obj,
			ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.DeleteCloudletPoolObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func UpdateCloudletPool(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletPool{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.CloudletPool.GetKey().GetTags())
	span.SetTag("org", in.CloudletPool.Key.Organization)
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.CloudletPool
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateCloudletPool(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzUpdateCloudletPool(ctx, rc.Region, rc.Username, obj,
			ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.UpdateCloudletPoolObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func ShowCloudletPool(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletPool{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.CloudletPool.GetKey().GetTags())
	span.SetTag("org", in.CloudletPool.Key.Organization)

	obj := &in.CloudletPool
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceCloudletPools, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.CloudletPool) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowCloudletPoolStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}

func AddCloudletPoolMember(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletPoolMember{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.CloudletPoolMember.GetKey().GetTags())
	span.SetTag("org", in.CloudletPoolMember.Key.Organization)

	obj := &in.CloudletPoolMember
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForAddCloudletPoolMember(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authzAddCloudletPoolMember(ctx, rc.Region, rc.Username, obj,
			ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.AddCloudletPoolMemberObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func RemoveCloudletPoolMember(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionCloudletPoolMember{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.CloudletPoolMember.GetKey().GetTags())
	span.SetTag("org", in.CloudletPoolMember.Key.Organization)

	obj := &in.CloudletPoolMember
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForRemoveCloudletPoolMember(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, obj.Key.Organization,
			ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.RemoveCloudletPoolMemberObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}
