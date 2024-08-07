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
	"runtime"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	trlog "github.com/opentracing/opentracing-go/log"
	jaeger "github.com/uber/jaeger-client-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Wrap Span so we can override Finish()
type Span struct {
	*jaeger.Span
	config    SpanConfig
	startTime time.Time // used when SuppressWithoutLogs is specified
}

var IgnoreLvl uint64 = 99999
var SamplingEnabled = true

type SpanConfig struct {
	Suppress            bool // ignore log for show commands etc
	NoTracing           bool // special span that only logs to disk
	SuppressWithoutLogs bool // ignore start, and ignore finish unless span has logs
	HasLogs             bool
	NoLogStartFinish    bool // don't write logs for start and finish, used when span is short and only for logging a single message
}

func (s *SpanConfig) ToOptions() []opentracing.StartSpanOption {
	ops := []opentracing.StartSpanOption{}
	if s.Suppress {
		ops = append(ops, WithSuppress{})
	}
	if s.NoTracing {
		ops = append(ops, WithNoTracing{})
	}
	if s.SuppressWithoutLogs {
		ops = append(ops, WithSuppressWithoutLogs{})
	}
	if s.HasLogs {
		ops = append(ops, WithHasLogs{})
	}
	if s.NoLogStartFinish {
		ops = append(ops, WithNoLogStartFinish{})
	}
	return ops
}

func StartSpan(lvl uint64, operationName string, opts ...opentracing.StartSpanOption) opentracing.Span {
	if tracer == nil {
		panic("tracer not initialized. Use log.InitTracer()")
	}

	// Add lineno tag if not specified by caller.
	// This check avoids duplicate calls to runtime.Caller() which
	// is expensive.
	var spanLineno *SpanLineno
	span := &Span{
		startTime: time.Now(),
	}
	for _, op := range opts {
		switch v := op.(type) {
		case SpanLineno:
			spanLineno = &v
		case WithSuppress:
			span.config.Suppress = true
		case WithNoTracing:
			span.config.NoTracing = true
		case WithSuppressWithoutLogs:
			span.config.SuppressWithoutLogs = true
		case WithHasLogs:
			span.config.HasLogs = true
		case WithNoLogStartFinish:
			span.config.NoLogStartFinish = true
		}
	}
	ospan := tracer.StartSpan(operationName, opts...)
	if span.config.Suppress {
		// log to span but not to disk, allows caller to decide
		// right before Finish whether or not to log the whole thing.
		ext.SamplingPriority.Set(ospan, 1)
	} else if lvl != IgnoreLvl {
		if DebugLevelSampled&lvl != 0 {
			if SamplingEnabled {
				// sampled
			} else {
				// always log
				ext.SamplingPriority.Set(ospan, 1)
			}
		} else if DebugLevelInfo&lvl != 0 || debugLevel&lvl != 0 {
			// always log (note DebugLevelInfo is always logged)
			ext.SamplingPriority.Set(ospan, 1)
		} else {
			// don't log
			ext.SamplingPriority.Set(ospan, 0)
		}
	}

	jspan, ok := ospan.(*jaeger.Span)
	if !ok {
		panic("non-jaeger span not supported")
	}
	span.Span = jspan

	// passing the option into StartSpan to try to set the tag didn't work
	// because of checking for sampling in jaeger code, so set lineno tag
	// after span is created here.
	lineno := ""
	if spanLineno != nil {
		lineno = spanLineno.lineno
	} else {
		lineno = GetLineno(1)
	}
	span.SetTag("lineno", lineno)

	if jspan.SpanContext().IsSampled() && !span.config.Suppress && !span.config.SuppressWithoutLogs && !span.config.NoLogStartFinish {
		spanlogger.Info(getSpanMsg(span, lineno, "start "+operationName))
	}

	return span
}

// This span only logs to disk, and does not actually do any tracing.
// It is primarily for use during init for logging to disk before Jaeger
// is initialized, or for unit tests.
func NoTracingSpan() opentracing.Span {
	span := &Span{
		config: SpanConfig{
			NoTracing: true,
		},
	}
	return span
}

func ChildSpan(ctx context.Context, lvl uint64, operationName string) (opentracing.Span, context.Context) {
	span := StartSpan(lvl, operationName, opentracing.ChildOf(SpanFromContext(ctx).Context()))
	return span, ContextWithSpan(context.Background(), span)
}

func ContextWithSpan(ctx context.Context, span opentracing.Span) context.Context {
	return opentracing.ContextWithSpan(ctx, span)
}

func SpanFromContext(ctx context.Context) opentracing.Span {
	return opentracing.SpanFromContext(ctx)
}

func SetTags(span opentracing.Span, tags map[string]string) {
	for k, v := range tags {
		span.SetTag(k, v)
	}
}

func GetTags(span opentracing.Span) map[string]interface{} {
	sp, ok := span.(*Span)
	if !ok {
		return make(map[string]interface{})
	}
	return sp.Span.Tags()
}

func SetContextTags(ctx context.Context, tags map[string]string) {
	SetTags(SpanFromContext(ctx), tags)
}

func SpanLog(ctx context.Context, lvl uint64, msg string, keysAndValues ...interface{}) {
	if debugLevel&lvl == 0 && lvl != DebugLevelInfo {
		return
	}
	ospan := opentracing.SpanFromContext(ctx)
	if ospan == nil {
		if noPanicOrphanedSpans {
			ospan = StartSpan(DebugLevelInfo, "orphaned")
			defer ospan.Finish()
		} else {
			panic("no span in context")
		}
	}
	span, ok := ospan.(*Span)
	if !ok {
		panic("non-edge-cloud Span not supported")
	}
	if !span.config.NoTracing && !span.SpanContext().IsSampled() {
		return
	}
	span.config.HasLogs = true

	lineno := GetLineno(1)
	if span.config.NoTracing {
		// just log to disk
		zfields := getFields(keysAndValues)
		spanlogger.Info(getSpanMsg(nil, lineno, msg), zfields...)
		return
	}
	fields := []trlog.Field{
		trlog.String("msg", msg),
		trlog.String("lineno", lineno),
	}
	kvfields, err := trlog.InterleavedKVToFields(keysAndValues...)
	if err != nil {
		FatalLog("SpanLog invalid args", "err", err)
	}
	fields = append(fields, kvfields...)
	span.LogFields(fields...)

	// Log to disk as well. Pull tags from span.
	// Unfortunately zap logger and opentracing logger, although
	// both implemented by uber, don't use the same Field struct.
	zfields := getFields(keysAndValues)
	// don't write to log file if deferring log decision
	if !span.config.Suppress {
		spanlogger.Info(getSpanMsg(span, lineno, msg), zfields...)
	}
}

func getFields(args []interface{}) []zap.Field {
	fields := []zap.Field{}
	for i := 0; i < len(args); {
		if i == len(args)-1 {
			panic("odd number of args")
		}
		k, v := args[i], args[i+1]
		// InterleavedKVToFields call ensures even number of args
		// and that key is a string
		if keystr, ok := k.(string); ok {
			fields = append(fields, zap.Any(keystr, v))
		}
		i += 2
	}
	return fields
}

// Convenience function for test routines. Does not require InitTracer().
func StartTestSpan(ctx context.Context, opts ...opentracing.StartSpanOption) context.Context {
	hasSpanLineno := false
	for _, op := range opts {
		if _, ok := op.(SpanLineno); ok {
			hasSpanLineno = true
		}
	}
	if !hasSpanLineno {
		opts = append(opts, WithSpanLineno(GetLineno(1)))
	}
	span := StartSpan(DebugLevelInfo, "test", opts...)
	// ignore span.Finish()
	return opentracing.ContextWithSpan(ctx, span)
}

func (s *Span) Tracer() opentracing.Tracer {
	if s.config.NoTracing {
		return nil
	}
	return s.Span.Tracer()
}

func (s *Span) Finish() {
	if s.config.Suppress || s.config.NoTracing {
		return
	}
	if s.config.SuppressWithoutLogs && !s.config.HasLogs {
		return
	}

	s.Span.Finish()

	if s.config.NoLogStartFinish {
		return
	}

	jspan := s.Span
	if !jspan.SpanContext().IsSampled() {
		return
	}

	lineno := GetLineno(1)

	fields := []zap.Field{}
	if s.config.SuppressWithoutLogs {
		// we didn't log start, so note time started here
		fields = append(fields, zap.Time("startTime", s.startTime))
	}
	for k, v := range jspan.Tags() {
		if IgnoreSpanTag(k) {
			continue
		}
		fields = append(fields, zap.Any(k, v))
	}
	msg := getSpanMsg(s, lineno, "finish "+s.OperationName())
	spanlogger.Info(msg, fields...)
}

func Unsuppress(ospan opentracing.Span) {
	s, ok := ospan.(*Span)
	if !ok {
		panic("non-edge-cloud Span not supported")
	}
	s.config.Suppress = false
}

func getSpanMsg(s *Span, lineno, msg string) string {
	traceid := "notrace"
	if s != nil {
		traceid = s.Span.SpanContext().TraceID().String()
	}
	return traceid + "\t" + lineno + "\t" + msg
}

func NoLogSpan(span opentracing.Span) {
	ext.SamplingPriority.Set(span, 0)
}

func ForceLogSpan(span opentracing.Span) {
	ext.SamplingPriority.Set(span, 1)
}

func GetLineno(skip int) string {
	ec := zapcore.NewEntryCaller(runtime.Caller(skip + 1))
	return ec.TrimmedPath()
}

type SpanLineno struct {
	lineno string
}

func (s SpanLineno) Apply(options *opentracing.StartSpanOptions) {}

func WithSpanLineno(lineno string) SpanLineno {
	return SpanLineno{
		lineno: lineno,
	}
}

// WithSuppress suppresses the span (effectively disables it)
type WithSuppress struct{}

func (s WithSuppress) Apply(options *opentracing.StartSpanOptions) {}

// WithNoTracing only logs to disk
type WithNoTracing struct{}

func (s WithNoTracing) Apply(options *opentracing.StartSpanOptions) {}

// WithSuppressWithoutLogs suppresses the span unless there are logs associated
// with the span. Note the start and finish log messages to disk are always
// skipped.
type WithSuppressWithoutLogs struct{}

func (s WithSuppressWithoutLogs) Apply(options *opentracing.StartSpanOptions) {}

// WithHasLogs is used to propagate the hasLogs state of a span across process API calls
type WithHasLogs struct{}

func (s WithHasLogs) Apply(options *opentracing.StartSpanOptions) {}

// WithNoLogStartFinish suppresses the file log for Start and Finish calls,
// used for very short spans created just to log a single log.
type WithNoLogStartFinish struct{}

func (s WithNoLogStartFinish) Apply(options *opentracing.StartSpanOptions) {}

func IgnoreSpanTag(tag string) bool {
	if tag == "internal.span.format" ||
		tag == "sampler.param" ||
		tag == "sampler.type" ||
		tag == "sampling.priority" ||
		tag == "span.kind" {
		return true
	}
	return false
}

func SpanTraceID(ctx context.Context) string {
	span := SpanFromContext(ctx)
	jspan, ok := span.(*Span)
	if !ok {
		panic("non-jaeger span not supported")
	}
	return jspan.SpanContext().TraceID().String()
}
