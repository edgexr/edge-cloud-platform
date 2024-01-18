// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ratelimit.proto

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

func ShowRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.RateLimitSettings.GetKey().GetTags())

	obj := &in.RateLimitSettings
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceConfig, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.RateLimitSettings) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowRateLimitSettingsStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}

func CreateFlowRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionFlowRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.FlowRateLimitSettings.GetKey().GetTags())

	obj := &in.FlowRateLimitSettings
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateFlowRateLimitSettings(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.CreateFlowRateLimitSettingsObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func UpdateFlowRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionFlowRateLimitSettings{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.FlowRateLimitSettings.GetKey().GetTags())
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.FlowRateLimitSettings
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateFlowRateLimitSettings(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.UpdateFlowRateLimitSettingsObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func DeleteFlowRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionFlowRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.FlowRateLimitSettings.GetKey().GetTags())

	obj := &in.FlowRateLimitSettings
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteFlowRateLimitSettings(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.DeleteFlowRateLimitSettingsObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func ShowFlowRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionFlowRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.FlowRateLimitSettings.GetKey().GetTags())

	obj := &in.FlowRateLimitSettings
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceConfig, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.FlowRateLimitSettings) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowFlowRateLimitSettingsStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}

func CreateMaxReqsRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionMaxReqsRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.MaxReqsRateLimitSettings.GetKey().GetTags())

	obj := &in.MaxReqsRateLimitSettings
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForCreateMaxReqsRateLimitSettings(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.CreateMaxReqsRateLimitSettingsObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func UpdateMaxReqsRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionMaxReqsRateLimitSettings{}
	dat, err := ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.MaxReqsRateLimitSettings.GetKey().GetTags())
	err = ormutil.SetRegionObjFields(dat, &in)
	if err != nil {
		return err
	}

	obj := &in.MaxReqsRateLimitSettings
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForUpdateMaxReqsRateLimitSettings(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.UpdateMaxReqsRateLimitSettingsObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func DeleteMaxReqsRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionMaxReqsRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.MaxReqsRateLimitSettings.GetKey().GetTags())

	obj := &in.MaxReqsRateLimitSettings
	log.SetContextTags(ctx, edgeproto.GetTags(obj))
	if err := obj.IsValidArgsForDeleteMaxReqsRateLimitSettings(); err != nil {
		return err
	}
	if !rc.SkipAuthz {
		if err := authorized(ctx, rc.Username, "",
			ResourceConfig, ActionManage); err != nil {
			return err
		}
	}

	resp, err := ctrlclient.DeleteMaxReqsRateLimitSettingsObj(ctx, rc, obj, connCache)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		return err
	}
	return ormutil.SetReply(c, resp)
}

func ShowMaxReqsRateLimitSettings(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	rc := &ormutil.RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.Username = claims.Username

	in := ormapi.RegionMaxReqsRateLimitSettings{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	rc.Region = in.Region
	rc.Database = database
	span := log.SpanFromContext(ctx)
	span.SetTag("region", in.Region)
	log.SetTags(span, in.MaxReqsRateLimitSettings.GetKey().GetTags())

	obj := &in.MaxReqsRateLimitSettings
	var authz *AuthzShow
	if !rc.SkipAuthz {
		authz, err = newShowAuthz(ctx, rc.Region, rc.Username, ResourceConfig, ActionView)
		if err != nil {
			return err
		}
	}

	cb := func(res *edgeproto.MaxReqsRateLimitSettings) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	}
	err = ctrlclient.ShowMaxReqsRateLimitSettingsStream(ctx, rc, obj, connCache, authz, cb)
	if err != nil {
		return err
	}
	return nil
}
