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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	jaeger "github.com/uber/jaeger-client-go"
	config "github.com/uber/jaeger-client-go/config"
	"github.com/uber/jaeger-client-go/log/zap"
)

var tracer opentracing.Tracer
var tracerCloser io.Closer
var reporterCloser io.Closer

type contextKey struct{}

var spanString = contextKey{}
var noPanicOrphanedSpans bool
var SpanServiceName string

var JaegerUnitTest bool

// InitTracer configures the Jaeger OpenTracing client to log traces.
// Set JAEGER_ENDPOINT to http://<jaegerhost>:14268/api/traces to
// specify the Jaeger server.
func InitTracer(tlsConfig *tls.Config) {
	if tracerCloser != nil {
		// already initialized. this happens in unit-tests
		return
	}
	SpanServiceName = filepath.Base(os.Args[0])

	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
		scheme := "https://"
		if tlsConfig == nil {
			scheme = "http://"
		}
		jaegerEndpoint = scheme + "localhost:14268/api/traces"
	}
	ur, err := url.Parse(jaegerEndpoint)
	if err != nil {
		panic(fmt.Sprintf("ERROR: failed to parse jaeger endpoint %s, %v", jaegerEndpoint, err))
	}

	if ur.Scheme == "" {
		// Set up client-side TLS
		if tlsConfig == nil {
			ur.Scheme = "http"
		} else {
			ur.Scheme = "https"
		}
	} else if ur.Scheme == "http" {
		// tls handled externally
		tlsConfig = nil
	}
	jaegerEndpoint = ur.String()

	// Configure Jaeger client
	// Note that we create the Reporter manually to be able to do mTLS
	rc := &config.ReporterConfig{
		CollectorEndpoint: jaegerEndpoint,
		QueueSize:         1000,
	}
	logger := zap.NewLogger(slogger.Desugar())
	reporter, rCloser := NewReporter(SpanServiceName, tlsConfig, rc, logger)

	cfg := &config.Configuration{
		ServiceName: SpanServiceName,
		Sampler: &config.SamplerConfig{
			Type:  jaeger.SamplerTypeProbabilistic,
			Param: 0.001,
		},
		RPCMetrics: true,
	}
	if strings.HasSuffix(os.Args[0], ".test") && !JaegerUnitTest {
		// unit test, don't bother reporting
		reporter = jaeger.NewNullReporter()
	}

	// Create tracer
	t, closer, err := cfg.NewTracer(
		config.Logger(logger),
		config.Reporter(reporter),
		config.MaxTagValueLength(4096),
	)
	if err != nil {
		panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
	}
	tracer = t
	tracerCloser = closer
	reporterCloser = rCloser
	opentracing.SetGlobalTracer(t)

	if _, found := os.LookupEnv("NO_PANIC_ORPHANED_SPANS"); found {
		// suppress the default behavior of panicking on
		// orphaned spans. This can be used for the main
		// deployment to prevent panicking.
		noPanicOrphanedSpans = true
	}
}

func FinishTracer() {
	if tracerCloser == nil {
		return
	}
	// reporter is closed as part of tracer Close() call
	tracerCloser.Close()
	tracerCloser = nil
	if reporterCloser != nil {
		reporterCloser.Close()
		reporterCloser = nil
	}
}

// TraceData is used to transport trace/span across boundaries,
// such as via etcd (stored on disk) or notify (cached in keys map).
type TraceData map[string]string

func (t TraceData) Set(key, val string) {
	t[key] = val
}

func (t TraceData) ForeachKey(handler func(key, val string) error) error {
	for k, v := range t {
		if err := handler(k, v); err != nil {
			return err
		}
	}
	return nil
}

type SpanCarrier struct {
	Data   TraceData
	Config SpanConfig
}

func SpanToString(ctx context.Context) string {
	span := SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	carrier := SpanCarrier{
		Data: TraceData{},
	}
	espan, ok := span.(*Span)
	if ok {
		if espan.config.NoTracing {
			return ""
		}
		carrier.Config = espan.config
	}
	tracer.Inject(span.Context(), opentracing.TextMap, carrier.Data)
	val, err := json.Marshal(carrier)
	if err != nil {
		return ""
	}
	return string(val)
}

func NewSpanFromString(lvl uint64, val, spanName string, opts ...opentracing.StartSpanOption) opentracing.Span {
	linenoOpt := WithSpanLineno(GetLineno(1))
	if val != "" {
		carrier := SpanCarrier{
			Data: TraceData{},
		}
		err := json.Unmarshal([]byte(val), &carrier)
		if err == nil {
			spanCtx, err := tracer.Extract(opentracing.TextMap, carrier.Data)
			if err == nil {
				opts = append(opts,
					ext.RPCServerOption(spanCtx),
					linenoOpt,
				)
				opts = append(opts, carrier.Config.ToOptions()...)
				return StartSpan(lvl, spanName, opts...)
			}
		}
	}
	opts = append(opts, linenoOpt)
	return StartSpan(lvl, spanName, opts...)
}
