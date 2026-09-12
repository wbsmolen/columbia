package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestDebugLogsExcludeCallerContent(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	resource := gatewayResource{metricsFactory: &MockMetricsFactory{}}
	for _, method := range []string{"private-method-marker", http.MethodPost} {
		req := httptest.NewRequest(method, "/private-path-marker?token=private-query-marker", nil)
		req.Header.Set("Content-Type", "private-content-marker")
		response := httptest.NewRecorder()
		resource.gatewayHandler(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status %d", response.Code)
		}
	}
	server := gatewayServer{}
	server.healthCheckHandler(httptest.NewRecorder(), httptest.NewRequest("private-health-method", "/private-health-path", nil))
	if strings.Contains(output.String(), "private-") {
		t.Fatalf("caller-derived content reached debug logs: %s", output.String())
	}
	if !strings.Contains(output.String(), `"status":400`) {
		t.Fatal("bounded failure status missing from debug logs")
	}
}
