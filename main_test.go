package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealthz(t *testing.T) {
	mux := newMux("http://unused", silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != `{"status":"ok"}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestProxyAllowed(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/rbac/allow" {
			t.Errorf("unexpected OPA path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":true}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())

	body := `{"input":{"sub":"user1","object":"/api/test","action":"GET"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/allow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"result":true`) {
		t.Fatalf("expected OPA body passthrough, got: %s", rec.Body.String())
	}
}

func TestProxyDenied(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":false}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())

	body := `{"input":{"sub":"user1","object":"/api/admin","action":"DELETE"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/allow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"forbidden"`) {
		t.Fatalf("expected forbidden body, got: %s", rec.Body.String())
	}
}

func TestProxyOPAUnreachable(t *testing.T) {
	mux := newMux("http://127.0.0.1:1", silentLogger())

	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/allow", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
}

func TestProxyOPAInvalidJSON(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())

	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/allow", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
}

func TestProxyForwardsHeaders(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("expected X-Custom header forwarded, got: %s", r.Header.Get("X-Custom"))
		}
		w.Write([]byte(`{"result":true}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())

	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/allow", strings.NewReader(`{}`))
	req.Header.Set("X-Custom", "test-value")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestProxyForwardsRequestBody(t *testing.T) {
	expectedBody := `{"input":{"sub":"abc","object":"/api/v1/clusters","action":"GET","app":"jinbe"}}`
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != expectedBody {
			t.Errorf("expected body %q, got %q", expectedBody, string(b))
		}
		w.Write([]byte(`{"result":true}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())

	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/allow", strings.NewReader(expectedBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestEnvHelper(t *testing.T) {
	if got := env("UNLIKELY_ENV_VAR_XYZ", "default"); got != "default" {
		t.Fatalf("expected fallback, got %q", got)
	}

	t.Setenv("UNLIKELY_ENV_VAR_XYZ", "custom")
	if got := env("UNLIKELY_ENV_VAR_XYZ", "default"); got != "custom" {
		t.Fatalf("expected custom, got %q", got)
	}
}
