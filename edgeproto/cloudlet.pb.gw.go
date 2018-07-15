// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: cloudlet.proto

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

func request_CloudletApi_CreateCloudlet_0(ctx context.Context, marshaler runtime.Marshaler, client CloudletApiClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq Cloudlet
	var metadata runtime.ServerMetadata

	if err := marshaler.NewDecoder(req.Body).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.CreateCloudlet(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func request_CloudletApi_DeleteCloudlet_0(ctx context.Context, marshaler runtime.Marshaler, client CloudletApiClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq Cloudlet
	var metadata runtime.ServerMetadata

	if err := marshaler.NewDecoder(req.Body).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.DeleteCloudlet(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func request_CloudletApi_UpdateCloudlet_0(ctx context.Context, marshaler runtime.Marshaler, client CloudletApiClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq Cloudlet
	var metadata runtime.ServerMetadata

	if err := marshaler.NewDecoder(req.Body).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.UpdateCloudlet(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func request_CloudletApi_ShowCloudlet_0(ctx context.Context, marshaler runtime.Marshaler, client CloudletApiClient, req *http.Request, pathParams map[string]string) (CloudletApi_ShowCloudletClient, runtime.ServerMetadata, error) {
	var protoReq Cloudlet
	var metadata runtime.ServerMetadata

	if err := marshaler.NewDecoder(req.Body).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.ShowCloudlet(ctx, &protoReq)
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

func request_CloudletInfoApi_ShowCloudletInfo_0(ctx context.Context, marshaler runtime.Marshaler, client CloudletInfoApiClient, req *http.Request, pathParams map[string]string) (CloudletInfoApi_ShowCloudletInfoClient, runtime.ServerMetadata, error) {
	var protoReq CloudletInfo
	var metadata runtime.ServerMetadata

	if err := marshaler.NewDecoder(req.Body).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.ShowCloudletInfo(ctx, &protoReq)
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

func request_CloudletMetricsApi_ShowCloudletMetrics_0(ctx context.Context, marshaler runtime.Marshaler, client CloudletMetricsApiClient, req *http.Request, pathParams map[string]string) (CloudletMetricsApi_ShowCloudletMetricsClient, runtime.ServerMetadata, error) {
	var protoReq CloudletMetrics
	var metadata runtime.ServerMetadata

	if err := marshaler.NewDecoder(req.Body).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	stream, err := client.ShowCloudletMetrics(ctx, &protoReq)
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

// RegisterCloudletApiHandlerFromEndpoint is same as RegisterCloudletApiHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterCloudletApiHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
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

	return RegisterCloudletApiHandler(ctx, mux, conn)
}

// RegisterCloudletApiHandler registers the http handlers for service CloudletApi to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterCloudletApiHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterCloudletApiHandlerClient(ctx, mux, NewCloudletApiClient(conn))
}

// RegisterCloudletApiHandlerClient registers the http handlers for service CloudletApi
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "CloudletApiClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "CloudletApiClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "CloudletApiClient" to call the correct interceptors.
func RegisterCloudletApiHandlerClient(ctx context.Context, mux *runtime.ServeMux, client CloudletApiClient) error {

	mux.Handle("POST", pattern_CloudletApi_CreateCloudlet_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_CloudletApi_CreateCloudlet_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_CloudletApi_CreateCloudlet_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_CloudletApi_DeleteCloudlet_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_CloudletApi_DeleteCloudlet_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_CloudletApi_DeleteCloudlet_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_CloudletApi_UpdateCloudlet_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_CloudletApi_UpdateCloudlet_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_CloudletApi_UpdateCloudlet_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_CloudletApi_ShowCloudlet_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_CloudletApi_ShowCloudlet_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_CloudletApi_ShowCloudlet_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_CloudletApi_CreateCloudlet_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"create", "cloudlet"}, ""))

	pattern_CloudletApi_DeleteCloudlet_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"delete", "cloudet"}, ""))

	pattern_CloudletApi_UpdateCloudlet_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"update", "cloudlet"}, ""))

	pattern_CloudletApi_ShowCloudlet_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"show", "cloudlet"}, ""))
)

var (
	forward_CloudletApi_CreateCloudlet_0 = runtime.ForwardResponseMessage

	forward_CloudletApi_DeleteCloudlet_0 = runtime.ForwardResponseMessage

	forward_CloudletApi_UpdateCloudlet_0 = runtime.ForwardResponseMessage

	forward_CloudletApi_ShowCloudlet_0 = runtime.ForwardResponseStream
)

// RegisterCloudletInfoApiHandlerFromEndpoint is same as RegisterCloudletInfoApiHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterCloudletInfoApiHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
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

	return RegisterCloudletInfoApiHandler(ctx, mux, conn)
}

// RegisterCloudletInfoApiHandler registers the http handlers for service CloudletInfoApi to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterCloudletInfoApiHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterCloudletInfoApiHandlerClient(ctx, mux, NewCloudletInfoApiClient(conn))
}

// RegisterCloudletInfoApiHandlerClient registers the http handlers for service CloudletInfoApi
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "CloudletInfoApiClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "CloudletInfoApiClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "CloudletInfoApiClient" to call the correct interceptors.
func RegisterCloudletInfoApiHandlerClient(ctx context.Context, mux *runtime.ServeMux, client CloudletInfoApiClient) error {

	mux.Handle("POST", pattern_CloudletInfoApi_ShowCloudletInfo_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_CloudletInfoApi_ShowCloudletInfo_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_CloudletInfoApi_ShowCloudletInfo_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_CloudletInfoApi_ShowCloudletInfo_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"show", "cloudletinfo"}, ""))
)

var (
	forward_CloudletInfoApi_ShowCloudletInfo_0 = runtime.ForwardResponseStream
)

// RegisterCloudletMetricsApiHandlerFromEndpoint is same as RegisterCloudletMetricsApiHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterCloudletMetricsApiHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
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

	return RegisterCloudletMetricsApiHandler(ctx, mux, conn)
}

// RegisterCloudletMetricsApiHandler registers the http handlers for service CloudletMetricsApi to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterCloudletMetricsApiHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterCloudletMetricsApiHandlerClient(ctx, mux, NewCloudletMetricsApiClient(conn))
}

// RegisterCloudletMetricsApiHandlerClient registers the http handlers for service CloudletMetricsApi
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "CloudletMetricsApiClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "CloudletMetricsApiClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "CloudletMetricsApiClient" to call the correct interceptors.
func RegisterCloudletMetricsApiHandlerClient(ctx context.Context, mux *runtime.ServeMux, client CloudletMetricsApiClient) error {

	mux.Handle("POST", pattern_CloudletMetricsApi_ShowCloudletMetrics_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cn, ok := w.(http.CloseNotifier); ok {
			go func(done <-chan struct{}, closed <-chan bool) {
				select {
				case <-done:
				case <-closed:
					cancel()
				}
			}(ctx.Done(), cn.CloseNotify())
		}
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_CloudletMetricsApi_ShowCloudletMetrics_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_CloudletMetricsApi_ShowCloudletMetrics_0(ctx, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_CloudletMetricsApi_ShowCloudletMetrics_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"show", "cloudletmetrics"}, ""))
)

var (
	forward_CloudletMetricsApi_ShowCloudletMetrics_0 = runtime.ForwardResponseStream
)
