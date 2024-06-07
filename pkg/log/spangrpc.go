// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const spanKey = "edgecloud-spankey"

func UnaryClientTraceGrpc(ctx context.Context, method string, req, resp interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	val := SpanToString(ctx)
	if val != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, spanKey, val)
	}
	return invoker(ctx, method, req, resp, cc, opts...)
}

func StreamClientTraceGrpc(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	val := SpanToString(ctx)
	if val != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, spanKey, val)
	}
	return streamer(ctx, desc, cc, method, opts...)
}

// NewSpanFromGrpc is used on server-side in controller/audit.go to extract span
func NewSpanFromGrpc(ctx context.Context, lvl uint64, spanName string) opentracing.Span {
	val := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals, ok := md[spanKey]; ok {
			val = vals[0]
		}
	}
	return NewSpanFromString(lvl, val, spanName)
}

// StartSpanHTTP is a server middleware that starts a span for the incoming request
// and adds it to the http.Request's context.
// If the sender sent a parent span, it creates a child span to continue the trace.
func StartSpanHTTP(r *http.Request) *http.Request {
	linenoOpt := WithSpanLineno(GetLineno(2))
	carrier := opentracing.HTTPHeadersCarrier(r.Header)
	spanCtx, err := tracer.Extract(opentracing.HTTPHeaders, carrier)
	var span opentracing.Span
	if err == nil {
		opts := []opentracing.StartSpanOption{
			ext.RPCServerOption(spanCtx),
			linenoOpt,
		}
		span = StartSpan(DebugLevelApi, r.RequestURI, opts...)
	} else {
		span = StartSpan(DebugLevelApi, r.RequestURI)
	}
	return r.WithContext(ContextWithSpan(r.Context(), span))
}

// HTTPTraceHandler is an http server middleware to ensure a span trace is present.
func HTTPTraceHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = StartSpanHTTP(r)
		next.ServeHTTP(w, r)
	})
}

// InjectTraceHTTP is used by a client to inject the current span into the request.
func InjectTraceHTTP(ctx context.Context, r *http.Request) error {
	carrier := opentracing.HTTPHeadersCarrier(r.Header)
	return tracer.Inject(SpanFromContext(ctx).Context(), opentracing.HTTPHeaders, carrier)
}

// EchoTraceHandler is an echo server middleware to ensure a span trace is present.
func EchoTraceHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := StartSpanHTTP(c.Request())
		c.SetRequest(r)
		return next(c)
	}
}
