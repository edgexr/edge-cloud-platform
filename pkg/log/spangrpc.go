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
	"time"

	opentracing "github.com/opentracing/opentracing-go"
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
	if err == nil {
		SpanLog(ctx, DebugLevelApi, "grpc client unary done", "method", method, "resp", resp, "dur", time.Since(start))
	} else {
		SpanLog(ctx, DebugLevelApi, "grpc client unary failed", "method", method, "resp", resp, "dur", time.Since(start), "err", err)
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
