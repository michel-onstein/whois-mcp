package obs

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TracerName identifies our spans.
const TracerName = "github.com/qjam/whois-mcp"

// TraceOptions configures tracing.
type TraceOptions struct {
	// Endpoint is an OTLP/HTTP collector. Empty disables export, which is the
	// default: a server that fails to start because no collector is configured
	// would be worse than one that simply is not traced.
	Endpoint string
	// ServiceName and ServiceVersion label the resource.
	ServiceName    string
	ServiceVersion string
	// SampleRatio is the head sampling ratio. Zero means always sample, which
	// is right for a low-volume server where the interesting request is rare.
	SampleRatio float64
}

// Shutdown flushes any pending spans.
type Shutdown func(context.Context) error

// InitTracing configures the global tracer and propagator.
//
// The propagator is set even when no exporter is configured. That is deliberate:
// the MCP spec's `_meta` conventions carry traceparent/tracestate/baggage from
// the agent, and propagating them means an agent's own trace links straight
// through to the registry call that was slow — which is useful whether or not we
// export spans ourselves.
func InitTracing(ctx context.Context, opt TraceOptions, log *slog.Logger) (trace.Tracer, Shutdown, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// W3C trace context plus baggage, which is what `_meta` carries.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if strings.TrimSpace(opt.Endpoint) == "" {
		log.Debug("tracing not exported; no WHOIS_MCP_OTEL_ENDPOINT configured")
		// A no-op tracer, so call sites need no nil checks and no conditionals.
		return noop.NewTracerProvider().Tracer(TracerName), func(context.Context) error { return nil }, nil
	}

	// Validate the endpoint ourselves. WithEndpointURL logs a parse failure and
	// falls back to its default host, which would quietly ship spans to
	// localhost:4318 instead of the collector an operator configured — a typo
	// that produces no error and no traces where they are expected.
	u, perr := url.Parse(opt.Endpoint)
	if perr != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil, fmt.Errorf("WHOIS_MCP_OTEL_ENDPOINT %q is not an absolute URL", opt.Endpoint)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, fmt.Errorf("WHOIS_MCP_OTEL_ENDPOINT %q must be http or https", opt.Endpoint)
	}

	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(opt.Endpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("creating OTLP trace exporter for %q: %w", opt.Endpoint, err)
	}

	sampler := sdktrace.AlwaysSample()
	if opt.SampleRatio > 0 && opt.SampleRatio < 1 {
		sampler = sdktrace.TraceIDRatioBased(opt.SampleRatio)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(resourceFor(opt)),
	)
	otel.SetTracerProvider(tp)
	log.Info("tracing enabled", "endpoint", opt.Endpoint)

	return tp.Tracer(TracerName), func(ctx context.Context) error {
		// A bounded flush: shutdown must not hang a deployment because a
		// collector is unreachable.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(ctx)
	}, nil
}

func resourceFor(opt TraceOptions) *resource.Resource {
	name := opt.ServiceName
	if name == "" {
		name = "whois-mcp"
	}
	attrs := []attribute.KeyValue{semconv.ServiceName(name)}
	if opt.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(opt.ServiceVersion))
	}
	// Merged with the default resource so process and SDK attributes survive.
	merged, err := resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL, attrs...))
	if err != nil {
		// A schema mismatch is not worth failing startup over; the unmerged
		// resource still identifies the service.
		return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
	}
	return merged
}

// UpstreamSpan starts a span for one upstream call.
//
// The domain is not an attribute. A trace is exportable telemetry and a query
// stream is itself sensitive (§12), so the host and protocol go in and the
// subject of the query stays out.
func UpstreamSpan(ctx context.Context, tr trace.Tracer, protocol, host string) (context.Context, trace.Span) {
	if tr == nil {
		return ctx, noop.Span{}
	}
	return tr.Start(ctx, protocol+" upstream",
		trace.WithAttributes(
			attribute.String("upstream.protocol", protocol),
			attribute.String("upstream.host", host),
		))
}
