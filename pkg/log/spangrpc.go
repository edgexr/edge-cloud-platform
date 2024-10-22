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
	"io"
	"net/http"
	strings "strings"
	"time"

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
	start := time.Now()
	SpanLog(ctx, DebugLevelApi, "grpc client unary start", "method", method, "req", req)
	err := invoker(ctx, method, req, resp, cc, opts...)
	logResp := resp
	if strings.Contains(method, "/edgeproto.CloudletAccessApi/") {
		// some of these APIs deliver certificates and private keys, do not log response
		logResp = "***redacted***"
	}
	if err == nil {
		SpanLog(ctx, DebugLevelApi, "grpc client unary done", "method", method, "resp", logResp, "dur", time.Since(start))
	} else {
		SpanLog(ctx, DebugLevelApi, "grpc client unary failed", "method", method, "resp", logResp, "dur", time.Since(start), "err", err)
	}
	return err
}

func StreamClientTraceGrpc(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	val := SpanToString(ctx)
	if val != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, spanKey, val)
	}
	clientStream, err := streamer(ctx, desc, cc, method, opts...)
	if err != nil {
		return nil, err
	}
	return &loggedClientStream{
		ClientStream: clientStream,
		ctx:          ctx,
		startTime:    time.Now(),
		method:       desc.StreamName,
	}, nil
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

type loggedClientStream struct {
	grpc.ClientStream
	ctx       context.Context
	startTime time.Time
	method    string
}

func (s *loggedClientStream) SendMsg(m any) error {
	SpanLog(s.ctx, DebugLevelApi, "grpc client stream send", "method", s.method, "obj", m)
	return s.ClientStream.SendMsg(m)
}

func (s *loggedClientStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	SpanLog(s.ctx, DebugLevelApi, "grpc client stream recv", "method", s.method, "obj", m, "err", err)
	if err == nil {
		return nil
	}
	if err == io.EOF {
		SpanLog(s.ctx, DebugLevelApi, "grpc client stream done", "method", s.method, "dur", time.Since(s.startTime))
	} else {
		SpanLog(s.ctx, DebugLevelApi, "grpc client stream failed", "method", s.method, "dur", time.Since(s.startTime), "err", err)
	}
	return err
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

// EchoTraceHandler is an echo server middleware to ensure a span trace is present.
func EchoTraceHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := StartSpanHTTP(c.Request())
		c.SetRequest(r)
		return next(c)
	}
}

func EchoAuditLogger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		ctx := req.Context()
		start := time.Now()
		SpanLog(ctx, DebugLevelApi, "echo api start", "method", req.Method, "path", req.RequestURI)
		err := next(c)
		if err == nil {
			SpanLog(ctx, DebugLevelApi, "echo api done", "method", req.Method, "path", req.RequestURI, "dur", time.Since(start))
		} else {
			SpanLog(ctx, DebugLevelApi, "echo api failed", "method", req.Method, "path", req.RequestURI, "dur", time.Since(start), "err", err)
		}
		return err
	}
}

// HTTPRequestDoer performs HTTP requests.
type HTTPRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPRequestDoerAuditor is a wrapper around HTTPRequestDoer
// for auto-generated clients from OpenAPI specs to audit requests.
type HTTPRequestDoerAuditor struct {
	Doer HTTPRequestDoer
}

func (s *HTTPRequestDoerAuditor) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	start := time.Now()
	reqURL := ""
	if req.URL != nil {
		reqURL = req.URL.String()
	}
	SpanLog(ctx, DebugLevelApi, "http request start", "method", req.Method, "url", reqURL)
	resp, err := s.Doer.Do(req)
	if err == nil {
		SpanLog(ctx, DebugLevelApi, "http request done", "method", req.Method, "url", reqURL, "status", resp.StatusCode, "dur", time.Since(start))
	} else {
		SpanLog(ctx, DebugLevelApi, "http request failed", "method", req.Method, "url", reqURL, "dur", time.Since(start), "err", err)
	}
	return resp, err
}
