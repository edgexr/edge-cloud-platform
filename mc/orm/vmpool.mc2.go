// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vmpool.proto

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

func CreateVMPool(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionVMPool{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.VMPool.GetKey().GetTags())
	span.SetTag("org", in.VMPool.Key.Organization)
	resp, err := CreateVMPoolObj(ctx, rc, &in.VMPool)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func CreateVMPoolObj(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPool) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.Organization,
			ResourceCloudlets, ActionManage, withRequiresOrg(obj.Key.Organization)); err != nil {
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
	api := edgeproto.NewVMPoolApiClient(rc.conn)
	return api.CreateVMPool(ctx, obj)
}

func DeleteVMPool(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionVMPool{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.VMPool.GetKey().GetTags())
	span.SetTag("org", in.VMPool.Key.Organization)
	resp, err := DeleteVMPoolObj(ctx, rc, &in.VMPool)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func DeleteVMPoolObj(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPool) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.Organization,
			ResourceCloudlets, ActionManage); err != nil {
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
	api := edgeproto.NewVMPoolApiClient(rc.conn)
	return api.DeleteVMPool(ctx, obj)
}

func UpdateVMPool(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionVMPool{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.VMPool.GetKey().GetTags())
	span.SetTag("org", in.VMPool.Key.Organization)
	resp, err := UpdateVMPoolObj(ctx, rc, &in.VMPool)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func UpdateVMPoolObj(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPool) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.Organization,
			ResourceCloudlets, ActionManage); err != nil {
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
	api := edgeproto.NewVMPoolApiClient(rc.conn)
	return api.UpdateVMPool(ctx, obj)
}

func ShowVMPool(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionVMPool{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.VMPool.GetKey().GetTags())
	span.SetTag("org", in.VMPool.Key.Organization)

	err = ShowVMPoolStream(ctx, rc, &in.VMPool, func(res *edgeproto.VMPool) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

func ShowVMPoolStream(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPool, cb func(res *edgeproto.VMPool)) error {
	var authz *AuthzShow
	var err error
	if !rc.skipAuthz {
		authz, err = newShowAuthz(ctx, rc.region, rc.username, ResourceCloudlets, ActionView)
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
	api := edgeproto.NewVMPoolApiClient(rc.conn)
	stream, err := api.ShowVMPool(ctx, obj)
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
			if !authz.Ok(res.Key.Organization) {
				continue
			}
		}
		cb(res)
	}
	return nil
}

func ShowVMPoolObj(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPool) ([]edgeproto.VMPool, error) {
	arr := []edgeproto.VMPool{}
	err := ShowVMPoolStream(ctx, rc, obj, func(res *edgeproto.VMPool) {
		arr = append(arr, *res)
	})
	return arr, err
}

func AddVMPoolMember(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionVMPoolMember{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.VMPoolMember.GetKey().GetTags())
	span.SetTag("org", in.VMPoolMember.Key.Organization)
	resp, err := AddVMPoolMemberObj(ctx, rc, &in.VMPoolMember)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func AddVMPoolMemberObj(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPoolMember) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.Organization,
			ResourceCloudlets, ActionManage); err != nil {
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
	api := edgeproto.NewVMPoolApiClient(rc.conn)
	return api.AddVMPoolMember(ctx, obj)
}

func RemoveVMPoolMember(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionVMPoolMember{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.VMPoolMember.GetKey().GetTags())
	span.SetTag("org", in.VMPoolMember.Key.Organization)
	resp, err := RemoveVMPoolMemberObj(ctx, rc, &in.VMPoolMember)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func RemoveVMPoolMemberObj(ctx context.Context, rc *RegionContext, obj *edgeproto.VMPoolMember) (*edgeproto.Result, error) {
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.Key.Organization,
			ResourceCloudlets, ActionManage); err != nil {
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
	api := edgeproto.NewVMPoolApiClient(rc.conn)
	return api.RemoveVMPoolMember(ctx, obj)
}
