// Package telemetry exports the server's activity to an OpenTelemetry collector:
// one span per decidable request, and a counter of policy decisions by severity.
// It is the fleet-observability path — the local audit chain answers "what did
// this one session do", telemetry answers "what is happening across the estate".
//
// It is the only package that imports the OpenTelemetry SDK; everything else sees
// a small surface (Middleware, RecordDecision, Shutdown). It is off unless a
// collector endpoint is configured — with no endpoint, nothing here is
// constructed, so the default build's behaviour is unchanged.
package telemetry

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Config configures the OTLP export. An empty Endpoint means disabled; the caller
// does not construct a Telemetry at all in that case.
type Config struct {
	// Endpoint is the OTLP/HTTP collector: "host:4318" (plaintext) or a full URL
	// like "https://collector.example:4318".
	Endpoint string
	// SampleRatio is the trace sampling ratio in [0,1]. Zero means "unset" and is
	// treated as 1 (sample everything), which is the useful default for a
	// low-volume desktop-automation session.
	SampleRatio float64
	// Headers are added to every OTLP request (auth), read from the environment by
	// the caller — never from the policy document.
	Headers     map[string]string
	ServiceName string
	Version     string
}

// Telemetry holds the OTLP providers and the instruments the server records to.
type Telemetry struct {
	traceProvider *sdktrace.TracerProvider
	meterProvider *sdkmetric.MeterProvider
	tracer        trace.Tracer
	decisions     metric.Int64Counter
}

// New builds the exporters and providers for an OTLP/HTTP collector.
func New(ctx context.Context, cfg Config) (*Telemetry, error) {
	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", orDefault(cfg.ServiceName, "windows-mcp-server")),
		attribute.String("service.version", orDefault(cfg.Version, "dev")),
	))
	if err != nil {
		return nil, fmt.Errorf("telemetry resource: %w", err)
	}

	traceExp, err := otlptracehttp.New(ctx, traceOptions(cfg)...)
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}
	metricExp, err := otlpmetrichttp.New(ctx, metricOptions(cfg)...)
	if err != nil {
		return nil, fmt.Errorf("otlp metric exporter: %w", err)
	}

	ratio := cfg.SampleRatio
	if ratio <= 0 {
		ratio = 1
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(ratio)),
	)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)

	decisions, err := mp.Meter("windows-mcp-server").Int64Counter(
		"policy_decisions_total",
		metric.WithDescription("Policy decisions, by severity and mode."),
	)
	if err != nil {
		return nil, fmt.Errorf("policy decisions counter: %w", err)
	}

	return &Telemetry{
		traceProvider: tp,
		meterProvider: mp,
		tracer:        tp.Tracer("windows-mcp-server"),
		decisions:     decisions,
	}, nil
}

// decidable are the methods worth a span: the ones that carry an action or a data
// egress. tools/list and the like pass through untraced.
var decidable = map[string]bool{
	"tools/call": true, "resources/read": true, "prompts/get": true,
}

// Middleware records one span per decidable request: the method, the tool name for
// a tool call, the duration, and whether it errored. Arguments are never put on a
// span — the same rule the audit chain follows.
func (t *Telemetry) Middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if !decidable[method] {
				return next(ctx, method, req)
			}
			ctx, span := t.tracer.Start(ctx, method)
			if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
				span.SetAttributes(attribute.String("mcp.tool", p.Name))
			}
			res, err := next(ctx, method, req)
			switch {
			case err != nil:
				span.SetStatus(codes.Error, err.Error())
			case isErrorResult(res):
				span.SetStatus(codes.Error, "tool returned an error result")
			}
			span.End()
			return res, err
		}
	}
}

// RecordDecision counts one policy decision. It is wired into the enforcement
// point, which is where a verdict is known.
func (t *Telemetry) RecordDecision(subject, severity, mode string) {
	t.decisions.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("severity", severity),
		attribute.String("mode", mode),
	))
}

// Shutdown flushes and closes the exporters. Errors are joined but non-fatal: a
// collector that is down must not stop the server from exiting cleanly.
func (t *Telemetry) Shutdown(ctx context.Context) {
	_ = t.traceProvider.Shutdown(ctx)
	_ = t.meterProvider.Shutdown(ctx)
}

func traceOptions(cfg Config) []otlptracehttp.Option {
	opts := []otlptracehttp.Option{}
	if strings.Contains(cfg.Endpoint, "://") {
		opts = append(opts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint), otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	return opts
}

func metricOptions(cfg Config) []otlpmetrichttp.Option {
	opts := []otlpmetrichttp.Option{}
	if strings.Contains(cfg.Endpoint, "://") {
		opts = append(opts, otlpmetrichttp.WithEndpointURL(cfg.Endpoint))
	} else {
		opts = append(opts, otlpmetrichttp.WithEndpoint(cfg.Endpoint), otlpmetrichttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}
	return opts
}

func isErrorResult(res mcp.Result) bool {
	ctr, ok := res.(*mcp.CallToolResult)
	return ok && ctr != nil && ctr.IsError
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ParseHeaders turns a "k1=v1,k2=v2" string (from an environment variable) into a
// header map. Blank entries are skipped; a value may contain '='.
func ParseHeaders(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
