package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientUsesVersionedBearerBoundary(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/machine/v1/enterprise/tenant" {
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("service bearer was not sent")
		}
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `{"id":"tenant-synthetic","status":"active"}`)
	}))
	defer server.Close()
	api, err := New(server.URL, "synthetic-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := api.Do(context.Background(), http.MethodGet, "/tenant", nil, &result); err != nil {
		t.Fatal(err)
	}
	if result["id"] != "tenant-synthetic" {
		t.Fatalf("unexpected tenant: %#v", result)
	}
}

func TestClientRejectsUnsafeConfigurationAndBoundsErrors(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{"", "http://example.invalid", "https://example.invalid?token=secret"} {
		if _, err := New(endpoint, "synthetic-token", time.Second); err == nil {
			t.Errorf("unsafe endpoint %q was accepted", endpoint)
		}
	}
	if _, err := New("https://example.invalid", "", time.Second); err == nil {
		t.Error("empty service token was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusConflict)
		fmt.Fprint(response, `{"error":"resource changed concurrently"}`)
	}))
	defer server.Close()
	api, err := New(server.URL, "synthetic-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = api.Do(context.Background(), http.MethodPut, "/groups/group-a", map[string]any{}, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 409: resource changed concurrently") {
		t.Fatalf("bounded API problem was not preserved: %v", err)
	}
	if err := api.Do(context.Background(), http.MethodGet, "/../identity", nil, nil); err == nil {
		t.Error("path traversal was accepted")
	}
}

func TestFindNeverFallsBackToAnotherIdentifier(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"items":[{"id":"group-a"}],"nextCursor":null}`)
	}))
	defer server.Close()
	api, err := New(server.URL, "synthetic-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := api.Find(context.Background(), "/groups", "group-b"); err != nil || found {
		t.Fatalf("wrong tenant resource matched: found=%v err=%v", found, err)
	}
}

func TestClientRefusesRedirectInsteadOfForwardingBearer(t *testing.T) {
	t.Parallel()
	redirected := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected <- struct{}{}
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	api, err := New(source.URL, "synthetic-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = api.Do(context.Background(), http.MethodGet, "/tenant", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect was not surfaced as an API error: %v", err)
	}
	select {
	case <-redirected:
		t.Error("machine API bearer was forwarded to a redirect target")
	default:
	}
}
