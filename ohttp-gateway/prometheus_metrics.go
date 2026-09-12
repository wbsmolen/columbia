// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusConfig struct {
	Host       string
	Port       string
	ScrapePath string
	MetricName string
}

type PrometheusMetrics struct {
	startedAt time.Time
	histogram prometheus.ObserverVec
}

func (p *PrometheusMetrics) Fire(result string) {
	observer := p.histogram.With(prometheus.Labels{
		"method": "unknown",
		"status": "unknown",
		"result": result,
	})
	p.observe(observer)
}

func (p *PrometheusMetrics) ResponseStatus(method string, status int) {
	observer := p.histogram.With(prometheus.Labels{
		"method": method,
		"status": fmt.Sprint(status),
		"result": "unknown",
	})
	p.observe(observer)
}

func (p *PrometheusMetrics) observe(observer prometheus.Observer) {
	// Prometheus's default histogram buckets are expressed in seconds.
	observer.Observe(time.Since(p.startedAt).Seconds())
}

type PrometheusMetricsFactory struct {
	histogram *prometheus.HistogramVec
}

func NewPrometheusMetricsFactory(config PrometheusConfig) (MetricsFactory, error) {
	factory, err := newPrometheusMetricsFactory(config.MetricName, prometheus.DefaultRegisterer)
	if err != nil {
		return nil, err
	}
	serveMux := http.NewServeMux()
	serveMux.Handle(config.ScrapePath, promhttp.Handler())
	server := http.Server{
		Addr:    net.JoinHostPort(config.Host, config.Port),
		Handler: serveMux,
	}

	go func() {
		slog.Debug("Listening for Prometheus scrapes", "host", config.Host, "port", config.Port)
		slog.Error("Error serving Prometheus scrapes", "error", server.ListenAndServe())
		os.Exit(1)
	}()

	return factory, nil
}

// Register once at startup, not on every request. A private constructor lets
// tests use an isolated registry without opening a scrape listener.
func newPrometheusMetricsFactory(metricName string, registerer prometheus.Registerer) (*PrometheusMetricsFactory, error) {
	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: metricName,
		Help: "Elapsed request time in seconds at each gateway processing stage.",
	}, []string{"eventName", "status", "method", "result"})

	if err := registerer.Register(histogram); err != nil {
		var registered prometheus.AlreadyRegisteredError
		if !errors.As(err, &registered) {
			return nil, err
		}
		var ok bool
		histogram, ok = registered.ExistingCollector.(*prometheus.HistogramVec)
		if !ok {
			return nil, fmt.Errorf("metric %q already registered with an incompatible collector", metricName)
		}
	}
	return &PrometheusMetricsFactory{histogram: histogram}, nil
}

func (p PrometheusMetricsFactory) Create(eventName string) Metrics {
	return &PrometheusMetrics{
		startedAt: time.Now(),
		histogram: p.histogram.MustCurryWith(prometheus.Labels{"eventName": eventName}),
	}
}
