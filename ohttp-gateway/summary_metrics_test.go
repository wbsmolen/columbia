package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type refusedUpstream struct{}

func (refusedUpstream) Handle(_ *http.Request, _ Metrics) (*http.Response, error) {
	return &http.Response{StatusCode: 403}, nil
}

func TestFilteredHandlerRecordsTargetRefusal(t *testing.T) {
	f := NewSummaryMetricsFactory(&MockMetricsFactory{})
	h := FilteredHttpRequestHandler{client: refusedUpstream{}}
	req, err := http.NewRequest(http.MethodGet, "https://example.test/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.Handle(req, f.Create(metricsEventGatewayRequest))
	if err != nil || resp.StatusCode != 403 {
		t.Fatalf("unexpected response: %v %v", resp, err)
	}
	found := false
	for _, row := range f.drain() {
		if row.Stage == "upstream" && row.Outcome == "403" {
			found = true
		}
	}
	if !found {
		t.Fatal("target refusal missing from operational summary")
	}
}

func TestSummaryMetricsSeparatesUpstreamAndOuterStatus(t *testing.T) {
	f := NewSummaryMetricsFactory(&MockMetricsFactory{})
	m := f.Create(metricsEventGatewayRequest)
	m.ResponseStatus("upstream", 403)
	m.Fire(metricsPayloadStatusPrefix + "200")
	m.ResponseStatus(http.MethodPost, 200)
	rows := f.drain()
	if len(rows) != 3 {
		t.Fatalf("got %d stages, want 3", len(rows))
	}
	want := map[string]string{"upstream": "403", "payload": "200", "outer": "200"}
	for _, row := range rows {
		if row.Outcome != want[row.Stage] || row.Count != 1 {
			t.Fatalf("unexpected row: %+v", row)
		}
	}
	if len(f.drain()) != 0 {
		t.Fatal("flush retained the previous window")
	}
}

func TestSummaryMetricsRejectsDynamicLabels(t *testing.T) {
	downstream := &MockMetricsFactory{}
	f := NewSummaryMetricsFactory(downstream)
	m := f.Create("person@example.com")
	m.Fire("https://private.example/content")
	m.ResponseStatus("token=secret", -123456)
	m.Fire(metricsPayloadStatusPrefix + "person@example.com")
	data, err := json.Marshal(map[string]any{
		"rows":           f.drain(),
		"exporterEvent":  downstream.metrics[0].eventName,
		"exporterLabels": downstream.metrics[0].resultLabels,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"person", "private", "token", "123456"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("dynamic label retained: %s", data)
		}
	}
}

func TestSummaryMetricsConcurrentCountsAndBuckets(t *testing.T) {
	f := NewSummaryMetricsFactory(&MockMetricsFactory{})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.record(metricsEventGatewayRequest, "outer", "200", 20*time.Millisecond) }()
	}
	wg.Wait()
	rows := f.drain()
	if len(rows) != 1 || rows[0].Count != 100 || rows[0].DurationBuckets[1] != 100 {
		t.Fatalf("lost samples: %+v", rows)
	}
}

func TestSummaryMetricsReportsActualCollectionWindow(t *testing.T) {
	f := NewSummaryMetricsFactory(&MockMetricsFactory{})
	start := time.Now()
	f.windowStart = start
	f.record(metricsEventGatewayRequest, "outer", "200", time.Second)
	rows, elapsed := f.drainWindow(start.Add(150 * time.Second))
	if elapsed != 150*time.Second || len(rows) != 1 || rows[0].Count != 1 {
		t.Fatalf("delayed flush lost its collection interval: elapsed=%v rows=%+v", elapsed, rows)
	}
	f.record(metricsEventGatewayRequest, "outer", "200", time.Second)
	rows, elapsed = f.drainWindow(start.Add(210 * time.Second))
	if elapsed != time.Minute || len(rows) != 1 || rows[0].Count != 1 {
		t.Fatalf("next interval did not reset at the previous drain: elapsed=%v rows=%+v", elapsed, rows)
	}
}
