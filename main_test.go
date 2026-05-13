package main

import (
	"encoding/json"
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

// ─── injectTenantID unit tests ──────────────────────────────────────

func TestInjectTenantID_NoHeaderLeavesBodyUnchanged(t *testing.T) {
	body := []byte(`{"input":{"sub":"u","object":"/x","action":"GET"}}`)
	out, mutated := injectTenantID(body, "")
	if mutated {
		t.Fatalf("expected no mutation when header is empty")
	}
	if string(out) != string(body) {
		t.Fatalf("body must be returned byte-equal, got %q", string(out))
	}
}

func TestInjectTenantID_InjectsOrgIDFromHeader(t *testing.T) {
	body := []byte(`{"input":{"sub":"u","object":"/x","action":"GET"}}`)
	out, mutated := injectTenantID(body, "tenant-uuid-here")
	if !mutated {
		t.Fatalf("expected mutation=true when header is present")
	}
	var parsed struct {
		Input struct {
			Sub            string `json:"sub"`
			OrganizationID string `json:"organization_id"`
		} `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed.Input.OrganizationID != "tenant-uuid-here" {
		t.Fatalf("expected organization_id injected, got %q", parsed.Input.OrganizationID)
	}
	if parsed.Input.Sub != "u" {
		t.Fatalf("expected existing input fields preserved, got sub=%q", parsed.Input.Sub)
	}
}

func TestInjectTenantID_HeaderOverridesExistingOrgID(t *testing.T) {
	// Single source of truth: the SPA header wins over any
	// organization_id that may have ridden in the body. Documented
	// in the comment on injectTenantID.
	body := []byte(`{"input":{"sub":"u","organization_id":"from-body"}}`)
	out, mutated := injectTenantID(body, "from-header")
	if !mutated {
		t.Fatalf("expected mutation when header is present even with existing field")
	}
	var parsed struct {
		Input struct {
			OrganizationID string `json:"organization_id"`
		} `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed.Input.OrganizationID != "from-header" {
		t.Fatalf("header must override body, got %q", parsed.Input.OrganizationID)
	}
}

func TestInjectTenantID_NonJSONBodyPassesThrough(t *testing.T) {
	body := []byte(`not json at all`)
	out, mutated := injectTenantID(body, "tenant-x")
	if mutated {
		t.Fatalf("non-JSON body must not be reported as mutated")
	}
	if string(out) != string(body) {
		t.Fatalf("non-JSON body must be returned unchanged")
	}
}

func TestInjectTenantID_BodyWithoutInputPassesThrough(t *testing.T) {
	body := []byte(`{"query":"data.rbac.simulate"}`)
	out, mutated := injectTenantID(body, "tenant-x")
	if mutated {
		t.Fatalf("body without input field must not be mutated")
	}
	if string(out) != string(body) {
		t.Fatalf("expected pass-through, got %q", string(out))
	}
}

func TestInjectTenantID_InputNotAnObjectPassesThrough(t *testing.T) {
	body := []byte(`{"input":"a string"}`)
	out, mutated := injectTenantID(body, "tenant-x")
	if mutated {
		t.Fatalf("non-object input must not be mutated")
	}
	if string(out) != string(body) {
		t.Fatalf("expected pass-through, got %q", string(out))
	}
}

// ─── End-to-end: X-Tenant-Id pipeline through the mux ───────────────

func TestProxyInjectsXTenantIdIntoOPAInput(t *testing.T) {
	var receivedBody []byte
	var receivedTenantHeader string
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedTenantHeader = r.Header.Get(tenantHeader)
		w.Write([]byte(`{"result":{"allow":true,"groups":[],"organizations":[],"reason":"ok"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	body := `{"input":{"sub":"u","object":"/api/x","action":"GET"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(tenantHeader, "11111111-1111-1111-1111-111111111111")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// OPA must see organization_id in input.
	var parsed struct {
		Input struct {
			OrganizationID string `json:"organization_id"`
		} `json:"input"`
	}
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("OPA received non-JSON body: %v (raw=%q)", err, string(receivedBody))
	}
	if parsed.Input.OrganizationID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("expected OPA to receive organization_id, got %q (full body=%q)",
			parsed.Input.OrganizationID, string(receivedBody))
	}

	// The proxy must NOT echo the inbound X-Tenant-Id header to OPA.
	// Rego reads input.organization_id, and trusting the header on
	// the OPA-bound request would just widen the surface.
	if receivedTenantHeader != "" {
		t.Fatalf("expected X-Tenant-Id to be stripped from OPA-bound request, got %q", receivedTenantHeader)
	}
}

func TestProxyOmitsOrgIDWhenHeaderAbsent(t *testing.T) {
	var receivedBody []byte
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"result":{"allow":true,"groups":[],"organizations":[],"reason":"ok"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	body := `{"input":{"sub":"u","object":"/api/x","action":"GET"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// no X-Tenant-Id header
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// Body should be byte-equal to what we sent.
	if string(receivedBody) != body {
		t.Fatalf("expected body unchanged when X-Tenant-Id absent, got %q", string(receivedBody))
	}
}

// ─── X-User-Organizations response header ───────────────────────────

func TestProxyForwardsXUserOrganizationsHeader(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":true,"groups":["readers"],"organizations":["org-a","org-b"],"reason":"ok"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	got := rec.Header().Get("X-User-Organizations")
	if got != `["org-a","org-b"]` {
		t.Fatalf("expected X-User-Organizations to be JSON array, got %q", got)
	}
}

func TestProxyEmitsEmptyOrganizationsHeaderWhenNone(t *testing.T) {
	// Mirrors X-User-Groups behaviour: header is always set so the
	// upstream sees a deterministic value even when the user has no
	// organizations.
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":true,"groups":[],"organizations":null,"reason":"ok"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-User-Organizations"); got != "[]" {
		t.Fatalf("expected empty JSON array, got %q", got)
	}
}

func TestProxyForwardsOrgsHeaderOnDeny(t *testing.T) {
	// The SPA's org switcher needs the list even on a 403 response so
	// it can re-render. Pin that the header rides along regardless of
	// allow verdict.
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":false,"groups":["readers"],"organizations":["org-a","org-b"],"reason":"forbidden_org"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-User-Organizations"); got != `["org-a","org-b"]` {
		t.Fatalf("expected X-User-Organizations on deny, got %q", got)
	}
}

// ─── X-Authz-Reason for each decision_reason value ──────────────────

func TestProxyForwardsAuthzReasonOK(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":true,"groups":[],"organizations":[],"reason":"ok"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Authz-Reason"); got != "ok" {
		t.Fatalf("expected reason=ok, got %q", got)
	}
}

func TestProxyForwardsAuthzReasonForbidden(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":false,"groups":[],"organizations":[],"reason":"forbidden"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Authz-Reason"); got != "forbidden" {
		t.Fatalf("expected reason=forbidden, got %q", got)
	}
}

func TestProxyForwardsAuthzReasonForbiddenOrg(t *testing.T) {
	// New reason added by the policies repo for the tenant gate.
	// Proxy must forward it verbatim — the rego owns the taxonomy.
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":false,"groups":["readers"],"organizations":["org-a"],"reason":"forbidden_org"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Authz-Reason"); got != "forbidden_org" {
		t.Fatalf("expected reason=forbidden_org, got %q", got)
	}
}

func TestProxyForwardsAuthzReasonNotFound(t *testing.T) {
	// not_found is still returned as 403 (oathkeeper's remote_json
	// authorizer protocol only accepts 200 or 403 from this hop;
	// the route-level 404 happens upstream from ingress-nginx).
	// The reason header carries the distinction for error-page.
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":false,"groups":[],"organizations":[],"reason":"not_found"}}`))
	}))
	defer opa.Close()

	mux := newMux(opa.URL, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/v1/data/rbac/decision", strings.NewReader(`{"input":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Pre-existing behaviour from commit ab20c40 mapped not_found to
	// HTTP 404. A follow-up (c8e8089) reverted that to 403 because
	// oathkeeper remote_json rejects non-200/403. Re-pin that the
	// status stays 403 while the reason rides in the header.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on not_found (oathkeeper compat), got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Authz-Reason"); got != "not_found" {
		t.Fatalf("expected reason=not_found, got %q", got)
	}
}
