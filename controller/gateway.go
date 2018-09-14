package main

import (
	"context"
	"net/http"

	"github.com/gogo/gateway"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/tls"
	"google.golang.org/grpc"
)

func grpcGateway(addr string, tlsCertFile string) (http.Handler, error) {
	ctx := context.Background()
	dialOption, err := tls.GetTLSClientDialOption(addr, tlsCertFile)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.DialContext(ctx, addr, dialOption)
	if err != nil {
		log.FatalLog("Failed to start REST gateway", "error", err)
	}

	jsonpb := &gateway.JSONPb{
		EmitDefaults: true,
		Indent:       " ",
		OrigName:     true,
	}
	mux := gwruntime.NewServeMux(
		// this avoids a marshaling issue with grpc-gateway and
		// gogo protobuf non-nullable embedded structs
		gwruntime.WithMarshalerOption(gwruntime.MIMEWildcard, jsonpb),
		// this is necessary to get error details properly
		// marshalled in unary requests
		gwruntime.WithProtoErrorHandler(gwruntime.DefaultHTTPProtoErrorHandler),
	)
	for _, f := range []func(context.Context, *gwruntime.ServeMux, *grpc.ClientConn) error{
		edgeproto.RegisterDeveloperApiHandler,
		edgeproto.RegisterAppApiHandler,
		edgeproto.RegisterAppInstApiHandler,
		edgeproto.RegisterOperatorApiHandler,
		edgeproto.RegisterCloudletApiHandler,
		edgeproto.RegisterCloudletInfoApiHandler,
		edgeproto.RegisterFlavorApiHandler,
		edgeproto.RegisterClusterFlavorApiHandler,
		edgeproto.RegisterClusterApiHandler,
		edgeproto.RegisterClusterInstApiHandler,
		edgeproto.RegisterControllerApiHandler,
		edgeproto.RegisterNodeApiHandler,
	} {
		if err := f(ctx, mux, conn); err != nil {
			return nil, err
		}
	}
	return mux, nil
}
