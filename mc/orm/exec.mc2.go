// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: exec.proto

package orm

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "github.com/labstack/echo"
import "net/http"
import "context"
import "github.com/mobiledgex/edge-cloud/log"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import "google.golang.org/grpc/status"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func RunCommand(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionExecRequest{}
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("org", in.ExecRequest.AppInstKey.AppKey.Organization)
	resp, err := RunCommandObj(ctx, rc, &in.ExecRequest)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func RunCommandObj(ctx context.Context, rc *RegionContext, obj *edgeproto.ExecRequest) (*edgeproto.ExecRequest, error) {
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.AppInstKey.AppKey.Organization,
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
	api := edgeproto.NewExecApiClient(rc.conn)
	return api.RunCommand(ctx, obj)
}

func RunConsole(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionExecRequest{}
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("org", in.ExecRequest.AppInstKey.AppKey.Organization)
	resp, err := RunConsoleObj(ctx, rc, &in.ExecRequest)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func RunConsoleObj(ctx context.Context, rc *RegionContext, obj *edgeproto.ExecRequest) (*edgeproto.ExecRequest, error) {
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.AppInstKey.AppKey.Organization,
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
	api := edgeproto.NewExecApiClient(rc.conn)
	return api.RunConsole(ctx, obj)
}

func ShowLogs(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionExecRequest{}
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	rc.region = in.Region
	span := log.SpanFromContext(ctx)
	span.SetTag("org", in.ExecRequest.AppInstKey.AppKey.Organization)
	resp, err := ShowLogsObj(ctx, rc, &in.ExecRequest)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func ShowLogsObj(ctx context.Context, rc *RegionContext, obj *edgeproto.ExecRequest) (*edgeproto.ExecRequest, error) {
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, obj.AppInstKey.AppKey.Organization,
			ResourceAppInsts, ActionView); err != nil {
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
	api := edgeproto.NewExecApiClient(rc.conn)
	return api.ShowLogs(ctx, obj)
}

func AccessCloudlet(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionExecRequest{}
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	rc.region = in.Region
	resp, err := AccessCloudletObj(ctx, rc, &in.ExecRequest)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
	}
	return setReply(c, err, resp)
}

func AccessCloudletObj(ctx context.Context, rc *RegionContext, obj *edgeproto.ExecRequest) (*edgeproto.ExecRequest, error) {
	if !rc.skipAuthz {
		if err := authorized(ctx, rc.username, "",
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
	api := edgeproto.NewExecApiClient(rc.conn)
	return api.AccessCloudlet(ctx, obj)
}
