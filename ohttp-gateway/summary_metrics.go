package main

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SummaryMetricsFactory supplements optional StatsD/Prometheus exporters with
// minute-level totals. Only closed stage/result labels and status codes enter
// this collector. It has no access to URLs, headers, identities or request IDs.
type SummaryMetricsFactory struct {
	downstream  MetricsFactory
	mu          sync.Mutex
	rows        map[summaryKey]*summaryRow
	windowStart time.Time
}

type summaryKey struct{ event, stage, outcome string }
type summaryRow struct {
	Event           string    `json:"event"`
	Stage           string    `json:"stage"`
	Outcome         string    `json:"outcome"`
	Count           uint64    `json:"count"`
	DurationBuckets [6]uint64 `json:"durationBuckets"`
}

func NewSummaryMetricsFactory(downstream MetricsFactory) *SummaryMetricsFactory {
	return &SummaryMetricsFactory{downstream: downstream, rows: make(map[summaryKey]*summaryRow), windowStart: time.Now()}
}

func (f *SummaryMetricsFactory) Create(event string) Metrics {
	switch event {
	case metricsEventGatewayRequest, metricsEventConfigsRequest:
	default:
		event = "other"
	}
	return &summaryMetrics{factory: f, inner: f.downstream.Create(event), event: event, started: time.Now()}
}

func (f *SummaryMetricsFactory) record(event, stage, outcome string, elapsed time.Duration) {
	key := summaryKey{event, stage, outcome}
	f.mu.Lock()
	defer f.mu.Unlock()
	row := f.rows[key]
	if row == nil {
		row = &summaryRow{Event: event, Stage: stage, Outcome: outcome}
		f.rows[key] = row
	}
	row.Count++
	bucket := 5
	for i, bound := range []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, time.Second, 5 * time.Second, 15 * time.Second} {
		if elapsed <= bound {
			bucket = i
			break
		}
	}
	row.DurationBuckets[bucket]++
}

func (f *SummaryMetricsFactory) drain() []summaryRow {
	rows, _ := f.drainWindow(time.Now())
	return rows
}

// A blocked logger or delayed ticker can make a window longer than a minute.
// Return the elapsed collection interval so callers calculate correct rates.
func (f *SummaryMetricsFactory) drainWindow(now time.Time) ([]summaryRow, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := make([]summaryRow, 0, len(f.rows))
	for _, row := range f.rows {
		rows = append(rows, *row)
	}
	f.rows = make(map[summaryKey]*summaryRow)
	elapsed := now.Sub(f.windowStart)
	f.windowStart = now
	return rows, elapsed
}

func (f *SummaryMetricsFactory) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if rows, elapsed := f.drainWindow(time.Now()); len(rows) > 0 {
				slog.Info("operational_summary", "windowSeconds", elapsed.Seconds(),
					"durationBoundsMs", []int{10, 100, 1000, 5000, 15000}, "metrics", rows)
			}
		}
	}
}

type summaryMetrics struct {
	factory *SummaryMetricsFactory
	inner   Metrics
	event   string
	started time.Time
}

func (m *summaryMetrics) Fire(result string) {
	// Binary/Proto handlers historically encode payload statuses in Fire.
	if suffix, ok := strings.CutPrefix(result, metricsPayloadStatusPrefix); ok {
		status, _ := strconv.Atoi(suffix)
		if status < 100 || status > 599 {
			status = 0
		}
		m.inner.Fire(metricsPayloadStatusPrefix + strconv.Itoa(status))
		m.recordStatus("payload", status)
		return
	}
	switch result {
	case metricsResultConfigurationMismatch, metricsResultDecapsulationFailed,
		metricsResultEncapsulationFailed, metricsResultContentDecodingFailed,
		metricsResultContentEncodingFailed, metricsResultRequestTranslationFailed,
		metricsResultResponseTranslationFailed, metricsResultTargetRequestForbidden,
		metricsResultTargetRequestFailed, metricsResultRateLimited, metricsResultSuccess,
		metricsResultConfigsUnavalable, metricsResultInvalidMethod,
		metricsResultInvalidContentType, metricsResultInvalidContent:
	default:
		result = "other"
	}
	m.inner.Fire(result)
	m.factory.record(m.event, "result", result, time.Since(m.started))
}

func (m *summaryMetrics) ResponseStatus(prefix string, status int) {
	switch prefix {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", metricsPayloadStatusPrefix, "upstream":
	default:
		prefix = "other"
	}
	if status < 100 || status > 599 {
		status = 0
	}
	m.inner.ResponseStatus(prefix, status)
	stage := "outer"
	if prefix == metricsPayloadStatusPrefix {
		stage = "payload"
	}
	if prefix == "upstream" {
		stage = "upstream"
	}
	m.recordStatus(stage, status)
}

func (m *summaryMetrics) recordStatus(stage string, status int) {
	outcome := "other"
	if status >= 100 && status <= 599 {
		outcome = strconv.Itoa(status)
	}
	m.factory.record(m.event, stage, outcome, time.Since(m.started))
}
