package orm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgecli "github.com/mobiledgex/edge-cloud/edgectl/cli"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	webrtc "github.com/pion/webrtc/v2"
	"google.golang.org/grpc/status"
)

func RunWebrtcStream(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return setReply(c, err, nil)
	}
	rc.username = claims.Username

	ws := GetWs(c)
	if ws == nil {
		err = fmt.Errorf("only websockets supported")
		return setReply(c, err, nil)
	}

	in := ormapi.RegionExecRequest{}
	success, err := ReadConn(c, &in)
	if !success {
		return setReply(c, err, nil)
	}
	rc.region = in.Region

	span := log.SpanFromContext(ctx)
	span.SetTag("org", in.ExecRequest.AppInstKey.AppKey.Organization)

	exchangeFunc := func(offer *webrtc.SessionDescription) (*edgeproto.ExecRequest, *webrtc.SessionDescription, error) {
		if offer != nil {
			offerBytes, err := json.Marshal(offer)
			if err != nil {
				return nil, nil, err
			}
			in.ExecRequest.Offer = string(offerBytes)
		}

		var reply *edgeproto.ExecRequest
		if strings.HasSuffix(c.Path(), "ctrl/RunCommand") {
			reply, err = RunCommandObj(ctx, rc, &in.ExecRequest)
		} else if strings.HasSuffix(c.Path(), "ctrl/ShowLogs") {
			reply, err = ShowLogsObj(ctx, rc, &in.ExecRequest)
		} else if strings.HasSuffix(c.Path(), "ctrl/RunConsole") {
			reply, err = RunConsoleObj(ctx, rc, &in.ExecRequest)
		} else if strings.HasSuffix(c.Path(), "ctrl/AccessCloudlet") {
			reply, err = AccessCloudletObj(ctx, rc, &in.ExecRequest)
		} else {
			return nil, nil, echo.ErrNotFound
		}

		if err != nil {
			if st, ok := status.FromError(err); ok {
				err = fmt.Errorf("%s", st.Message())
			}
			return nil, nil, err
		}

		if reply.Err != "" {
			return nil, nil, fmt.Errorf("%s", reply.Err)
		}
		if offer != nil {
			if reply.Answer == "" {
				return nil, nil, fmt.Errorf("empty answer")
			}
			answer := webrtc.SessionDescription{}
			err = json.Unmarshal([]byte(reply.Answer), &answer)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to unmarshal answer %s, %v",
					reply.Answer, err)
			}
			return reply, &answer, nil
		}
		return reply, nil, nil
	}
	if in.ExecRequest.Webrtc {
		err = edgecli.RunWebrtc(&in.ExecRequest, exchangeFunc, ws, edgecli.SetupLocalConsoleTunnel)
	} else {
		err = edgecli.RunEdgeTurn(&in.ExecRequest, exchangeFunc, ws)
	}
	return setReply(c, err, nil)
}
