// Columbia - regression tests for response-side error status mapping.
// SPDX-License-Identifier: BSD-3-Clause
//
// A target response body that fails MID-READ (e.g. the target resets the
// connection while streaming) is an upstream/server problem. The inner
// (encapsulated) status must be 500, NOT 400: clients fail open on 5xx but
// treat 4xx as a hard error, so mapping this to 400 turned transient upstream
// hiccups into user-visible failures.

package main

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/chris-wood/ohttp-go"
	"google.golang.org/protobuf/proto"
)

// midReadErrorBody yields a few bytes, then fails, like a connection reset
// partway through a target response.
type midReadErrorBody struct {
	sent bool
}

func (b *midReadErrorBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, []byte("partial")), nil
	}
	return 0, errors.New("mid-stream body read failure")
}

// BrokenBodyHTTPRequestHandler returns a 200 whose body errors mid-read.
type BrokenBodyHTTPRequestHandler struct{}

func (d BrokenBodyHTTPRequestHandler) Handle(req *http.Request, metrics Metrics) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(&midReadErrorBody{}),
	}, nil
}

func TestBinaryHTTPHandlerBodyReadErrorYields500(t *testing.T) {
	factory := &MockMetricsFactory{}
	handler := BinaryHTTPAppHandler{httpHandler: BrokenBodyHTTPRequestHandler{}}

	httpRequest, err := http.NewRequest(http.MethodGet, "https://allowed.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	binaryRequest := ohttp.BinaryRequest(*httpRequest)
	encodedRequest, err := binaryRequest.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	respEnc, err := handler.Handle(encodedRequest, factory.Create(metricsEventGatewayRequest))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ohttp.UnmarshalBinaryResponse(respEnc)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("body read failure yielded inner status %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestProtoHTTPHandlerBodyReadErrorYields500(t *testing.T) {
	factory := &MockMetricsFactory{}
	handler := ProtoHTTPAppHandler{httpHandler: BrokenBodyHTTPRequestHandler{}}

	httpRequest, err := http.NewRequest(http.MethodGet, "https://allowed.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	protoRequest, err := requestToProtoHTTP(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	encodedRequest, err := proto.Marshal(protoRequest)
	if err != nil {
		t.Fatal(err)
	}

	respEnc, err := handler.Handle(encodedRequest, factory.Create(metricsEventGatewayRequest))
	if err != nil {
		t.Fatal(err)
	}

	resp := &Response{}
	if err := proto.Unmarshal(respEnc, resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("body read failure yielded inner status %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}
