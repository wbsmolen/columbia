package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type countingRegisterer struct {
	prometheus.Registerer
	calls int
}

func (r *countingRegisterer) Register(collector prometheus.Collector) error {
	r.calls++
	return r.Registerer.Register(collector)
}

func TestPrometheusRegistersOnceForManyRequests(t *testing.T) {
	registry := prometheus.NewRegistry()
	registerer := &countingRegisterer{Registerer: registry}
	factory, err := newPrometheusMetricsFactory("test_gateway_duration", registerer)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		factory.Create(metricsEventGatewayRequest).ResponseStatus("POST", 200)
	}
	if registerer.calls != 1 {
		t.Fatalf("collector registered %d times, want once", registerer.calls)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 1 || len(families[0].Metric) != 1 || families[0].Metric[0].GetHistogram().GetSampleCount() != 100 {
		t.Fatalf("request observations were not shared: %+v", families)
	}
}

func TestPrometheusDurationsUseSeconds(t *testing.T) {
	registry := prometheus.NewRegistry()
	factory, err := newPrometheusMetricsFactory("test_gateway_seconds", registry)
	if err != nil {
		t.Fatal(err)
	}
	metrics := factory.Create(metricsEventGatewayRequest).(*PrometheusMetrics)
	metrics.startedAt = time.Now().Add(-time.Second)
	metrics.ResponseStatus("POST", 200)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	histogram := families[0].Metric[0].GetHistogram()
	if sum := histogram.GetSampleSum(); sum < 1 || sum >= 10 {
		t.Fatalf("one-second request observed as %g; default buckets require seconds", sum)
	}
	buckets := histogram.GetBucket()
	if len(buckets) == 0 || buckets[len(buckets)-1].GetCumulativeCount() != 1 {
		t.Fatal("one-second request incorrectly overflowed every default bucket")
	}
}

func TestPrometheusFactoryReusesAnExistingCollector(t *testing.T) {
	registry := prometheus.NewRegistry()
	first, err := newPrometheusMetricsFactory("test_gateway_shared", registry)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newPrometheusMetricsFactory("test_gateway_shared", registry)
	if err != nil {
		t.Fatal(err)
	}
	if first.histogram != second.histogram {
		t.Fatal("same metric registered with separate collectors")
	}
}

func TestPrometheusRegistrationErrorReturnedAtStartup(t *testing.T) {
	registry := prometheus.NewRegistry()
	if _, err := newPrometheusMetricsFactory("not a metric name", registry); err == nil {
		t.Fatal("invalid metric configuration must fail at startup")
	}
}
