package telemetry

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/straja-ai/straja/internal/redact"
)

// Config controls telemetry setup.
type Config struct {
	Enabled  bool
	Endpoint string
	Protocol string // grpc | http
	Service  string
	Version  string
}

// Provider wires tracer/meter providers and exposes helpers.
type Provider struct {
	Enabled bool
	tracer  trace.Tracer
	meter   metric.Meter

	requestsCounter       metric.Int64Counter
	requestDuration       metric.Float64Histogram
	upstreamDuration      metric.Float64Histogram
	strajaGuardDuration   metric.Float64Histogram
	policyHitsCounter     metric.Int64Counter
	shutdownTraceProvider func(context.Context) error
	shutdownMeterProvider func(context.Context) error
}

// NewProvider configures OTEL exporters + providers. When disabled, returns no-op providers.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !cfg.Enabled {
		no := &Provider{
			Enabled: false,
			tracer:  trace.NewNoopTracerProvider().Tracer(""),
			meter:   noop.NewMeterProvider().Meter(""),
		}
		no.initInstruments()
		return no, nil
	}

	redact.Logf("telemetry enabled (OpenTelemetry OTLP %s) endpoint=%s; if no collector is listening, periodic 'failed to upload metrics' warnings are expected", strings.ToLower(cfg.Protocol), cfg.Endpoint)

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			attribute.String("service.name", cfg.Service),
			attribute.String("service.version", cfg.Version),
		),
	)
	if err != nil {
		return nil, err
	}

	var tp *sdktrace.TracerProvider

	switch strings.ToLower(cfg.Protocol) {
	case "", "grpc":
		exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(cfg.Endpoint), otlptracegrpc.WithInsecure())
		if err != nil {
			return nil, err
		}
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
	case "http":
		exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(cfg.Endpoint), otlptracehttp.WithInsecure())
		if err != nil {
			return nil, err
		}
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
	default:
		return nil, nil
	}

	otel.SetTracerProvider(tp)

	var metricExporter sdkmetric.Reader
	switch strings.ToLower(cfg.Protocol) {
	case "", "grpc":
		exp, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpoint(cfg.Endpoint), otlpmetricgrpc.WithInsecure())
		if err != nil {
			return nil, err
		}
		metricExporter = sdkmetric.NewPeriodicReader(exp)
	case "http":
		exp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpoint(cfg.Endpoint), otlpmetrichttp.WithInsecure())
		if err != nil {
			return nil, err
		}
		metricExporter = sdkmetric.NewPeriodicReader(exp)
	}

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(metricExporter))
	otel.SetMeterProvider(mp)

	p := &Provider{
		Enabled:               true,
		tracer:                tp.Tracer("straja"),
		meter:                 mp.Meter("straja"),
		shutdownTraceProvider: tp.Shutdown,
		shutdownMeterProvider: func(ctx context.Context) error {
			if mp != nil {
				return mp.Shutdown(ctx)
			}
			return nil
		},
	}
	p.initInstruments()
	return p, nil
}

func (p *Provider) initInstruments() {
	if p == nil {
		return
	}
	// Use meter to create instruments; ignore errors to keep telemetry best-effort.
	p.requestsCounter, _ = p.meter.Int64Counter("straja_requests_total")
	p.requestDuration, _ = p.meter.Float64Histogram("straja_request_duration_ms")
	p.upstreamDuration, _ = p.meter.Float64Histogram("straja_upstream_duration_ms")
	p.strajaGuardDuration, _ = p.meter.Float64Histogram("straja_strajaguard_inference_duration_ms")
	p.policyHitsCounter, _ = p.meter.Int64Counter("straja_policy_hits_total")
}

// Tracer returns the tracer.
func (p *Provider) Tracer() trace.Tracer {
	if p == nil {
		return trace.NewNoopTracerProvider().Tracer("")
	}
	return p.tracer
}

// Meter returns the meter.
func (p *Provider) Meter() metric.Meter {
	if p == nil {
		return noop.NewMeterProvider().Meter("")
	}
	return p.meter
}

// Shutdown flushes providers.
func (p *Provider) Shutdown(ctx context.Context) {
	if p == nil {
		return
	}
	if p.shutdownTraceProvider != nil {
		_ = p.shutdownTraceProvider(ctx)
	}
	if p.shutdownMeterProvider != nil {
		_ = p.shutdownMeterProvider(ctx)
	}
}

// RecordRequestMetrics emits counters/histograms with safe labels.
func (p *Provider) RecordRequestMetrics(decision, providerType, projectID string, durMs float64, upstreamMs float64, sgMs float64, policyHits int) {
	if p == nil {
		return
	}
	labels := []attribute.KeyValue{
		attribute.String("straja.decision", decision),
		attribute.String("straja.provider_type", providerType),
		attribute.String("straja.project_id", projectID),
	}
	p.requestsCounter.Add(context.Background(), 1, metric.WithAttributes(labels...))
	p.requestDuration.Record(context.Background(), durMs, metric.WithAttributes(labels...))
	if upstreamMs > 0 {
		p.upstreamDuration.Record(context.Background(), upstreamMs, metric.WithAttributes(labels...))
	}
	if sgMs > 0 {
		p.strajaGuardDuration.Record(context.Background(), sgMs, metric.WithAttributes(labels...))
	}
	if policyHits > 0 {
		p.policyHitsCounter.Add(context.Background(), int64(policyHits), metric.WithAttributes(labels...))
	}
}
