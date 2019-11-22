// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: app_inst.proto

/*
Package edgeproto is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package edgeproto

import (
	"io"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/utilities"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/status"
)

var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray

func request_AppInstApi_CreateAppInst_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstApiClient, req *http.Request, pathParams map[string]string) (AppInstApi_CreateAppInstClient, runtime.ServerMetadata, error) {
	var protoReq AppInst
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.CreateAppInst(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_AppInstApi_DeleteAppInst_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstApiClient, req *http.Request, pathParams map[string]string) (AppInstApi_DeleteAppInstClient, runtime.ServerMetadata, error) {
	var protoReq AppInst
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.DeleteAppInst(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_AppInstApi_RefreshAppInst_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstApiClient, req *http.Request, pathParams map[string]string) (AppInstApi_RefreshAppInstClient, runtime.ServerMetadata, error) {
	var protoReq AppInst
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.RefreshAppInst(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_AppInstApi_UpdateAppInst_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstApiClient, req *http.Request, pathParams map[string]string) (AppInstApi_UpdateAppInstClient, runtime.ServerMetadata, error) {
	var protoReq AppInst
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.UpdateAppInst(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_AppInstApi_ShowAppInst_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstApiClient, req *http.Request, pathParams map[string]string) (AppInstApi_ShowAppInstClient, runtime.ServerMetadata, error) {
	var protoReq AppInst
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.ShowAppInst(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_AppInstInfoApi_ShowAppInstInfo_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstInfoApiClient, req *http.Request, pathParams map[string]string) (AppInstInfoApi_ShowAppInstInfoClient, runtime.ServerMetadata, error) {
	var protoReq AppInstInfo
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.ShowAppInstInfo(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_AppInstMetricsApi_ShowAppInstMetrics_0(ctx context.Context, marshaler runtime.Marshaler, client AppInstMetricsApiClient, req *http.Request, pathParams map[string]string) (AppInstMetricsApi_ShowAppInstMetricsClient, runtime.ServerMetadata, error) {
	var protoReq AppInstMetrics
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.ShowAppInstMetrics(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

// RegisterAppInstApiHandlerFromEndpoint is same as RegisterAppInstApiHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterAppInstApiHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterAppInstApiHandler(ctx, mux, conn)
}

// RegisterAppInstApiHandler registers the http handlers for service AppInstApi to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterAppInstApiHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterAppInstApiHandlerClient(ctx, mux, NewAppInstApiClient(conn))
}

// RegisterAppInstApiHandlerClient registers the http handlers for service AppInstApi
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "AppInstApiClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "AppInstApiClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "AppInstApiClient" to call the correct interceptors.
func RegisterAppInstApiHandlerClient(ctx context.Context, mux *runtime.ServeMux, client AppInstApiClient) error {

	mux.Handle("POST", pattern_AppInstApi_CreateAppInst_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstApi_CreateAppInst_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstApi_CreateAppInst_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_AppInstApi_DeleteAppInst_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstApi_DeleteAppInst_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstApi_DeleteAppInst_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_AppInstApi_RefreshAppInst_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstApi_RefreshAppInst_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstApi_RefreshAppInst_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_AppInstApi_UpdateAppInst_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstApi_UpdateAppInst_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstApi_UpdateAppInst_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_AppInstApi_ShowAppInst_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstApi_ShowAppInst_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstApi_ShowAppInst_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_AppInstApi_CreateAppInst_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"create", "appinst"}, ""))

	pattern_AppInstApi_DeleteAppInst_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"delete", "appinst"}, ""))

	pattern_AppInstApi_RefreshAppInst_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"refresh", "appinst"}, ""))

	pattern_AppInstApi_UpdateAppInst_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"update", "appinst"}, ""))

	pattern_AppInstApi_ShowAppInst_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"show", "appinst"}, ""))
)

var (
	forward_AppInstApi_CreateAppInst_0 = runtime.ForwardResponseStream

	forward_AppInstApi_DeleteAppInst_0 = runtime.ForwardResponseStream

	forward_AppInstApi_RefreshAppInst_0 = runtime.ForwardResponseStream

	forward_AppInstApi_UpdateAppInst_0 = runtime.ForwardResponseStream

	forward_AppInstApi_ShowAppInst_0 = runtime.ForwardResponseStream
)

// RegisterAppInstInfoApiHandlerFromEndpoint is same as RegisterAppInstInfoApiHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterAppInstInfoApiHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterAppInstInfoApiHandler(ctx, mux, conn)
}

// RegisterAppInstInfoApiHandler registers the http handlers for service AppInstInfoApi to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterAppInstInfoApiHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterAppInstInfoApiHandlerClient(ctx, mux, NewAppInstInfoApiClient(conn))
}

// RegisterAppInstInfoApiHandlerClient registers the http handlers for service AppInstInfoApi
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "AppInstInfoApiClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "AppInstInfoApiClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "AppInstInfoApiClient" to call the correct interceptors.
func RegisterAppInstInfoApiHandlerClient(ctx context.Context, mux *runtime.ServeMux, client AppInstInfoApiClient) error {

	mux.Handle("POST", pattern_AppInstInfoApi_ShowAppInstInfo_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstInfoApi_ShowAppInstInfo_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstInfoApi_ShowAppInstInfo_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_AppInstInfoApi_ShowAppInstInfo_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"show", "appinstinfo"}, ""))
)

var (
	forward_AppInstInfoApi_ShowAppInstInfo_0 = runtime.ForwardResponseStream
)

// RegisterAppInstMetricsApiHandlerFromEndpoint is same as RegisterAppInstMetricsApiHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterAppInstMetricsApiHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterAppInstMetricsApiHandler(ctx, mux, conn)
}

// RegisterAppInstMetricsApiHandler registers the http handlers for service AppInstMetricsApi to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterAppInstMetricsApiHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterAppInstMetricsApiHandlerClient(ctx, mux, NewAppInstMetricsApiClient(conn))
}

// RegisterAppInstMetricsApiHandlerClient registers the http handlers for service AppInstMetricsApi
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "AppInstMetricsApiClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "AppInstMetricsApiClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "AppInstMetricsApiClient" to call the correct interceptors.
func RegisterAppInstMetricsApiHandlerClient(ctx context.Context, mux *runtime.ServeMux, client AppInstMetricsApiClient) error {

	mux.Handle("POST", pattern_AppInstMetricsApi_ShowAppInstMetrics_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AppInstMetricsApi_ShowAppInstMetrics_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AppInstMetricsApi_ShowAppInstMetrics_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_AppInstMetricsApi_ShowAppInstMetrics_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"show", "appinstmetrics"}, ""))
)

var (
	forward_AppInstMetricsApi_ShowAppInstMetrics_0 = runtime.ForwardResponseStream
)
