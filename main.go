package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
)

// tenantHeader is the request header the SPA attaches after the user
// picks an organization. opa-authz-proxy promotes it into the OPA
// decision payload as `input.organization_id` so rego can enforce
// the Path 3 hybrid tenant gate without trusting client-side data
// any further than this single hop.
const tenantHeader = "X-Tenant-Id"

// injectTenantID rewrites the incoming OPA decision body to set
// `input.organization_id` from the request's X-Tenant-Id header.
// The header value is authoritative: if both header and an existing
// body field are present, the header wins (single source of truth =
// the SPA's currently-selected org).
//
// Returns the (possibly mutated) body bytes, and true when a mutation
// happened. Non-JSON bodies, non-object inputs, and bodies that
// don't carry an "input" key are returned unchanged.
func injectTenantID(body []byte, tenantID string) ([]byte, bool) {
	if tenantID == "" {
		return body, false
	}
	// Decode into a generic map so we don't lose unknown fields.
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return body, false
	}
	rawInput, ok := envelope["input"]
	if !ok {
		return body, false
	}
	input, ok := rawInput.(map[string]any)
	if !ok {
		return body, false
	}
	input["organization_id"] = tenantID
	envelope["input"] = input
	mutated, err := json.Marshal(envelope)
	if err != nil {
		return body, false
	}
	return mutated, true
}

func main() {
	upstream := env("OPA_UPSTREAM_URL", "http://localhost:8181")
	addr := env("LISTEN_ADDR", ":8080")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	mux := newMux(upstream, logger)

	logger.Info("starting opa-authz-proxy", "addr", addr, "upstream", upstream)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func newMux(upstream string, logger *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		opaURL := upstream + r.URL.Path

		// Read the incoming body once so we can (a) optionally rewrite
		// it to carry `input.organization_id` from the X-Tenant-Id
		// header, and (b) still hand a fresh io.Reader to OPA. Bound
		// the read with http.MaxBytesReader-style behaviour via the
		// surrounding server defaults — Go's net/http already caps
		// request bodies based on Server.MaxHeaderBytes for the
		// header and the http2 default frame size for the body; for
		// a /v1/data POST these caps are well above anything legitimate.
		var bodyBytes []byte
		if r.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				logger.Error("failed to read request body", "error", err)
				http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
				return
			}
			r.Body.Close()
		}

		// Promote X-Tenant-Id into the OPA input payload when present.
		// The mutation is best-effort: a non-JSON body or a body that
		// doesn't carry an `input` object passes through unchanged so
		// non-decision endpoints (e.g. /v1/data with a custom query)
		// keep working.
		mutated, didInject := injectTenantID(bodyBytes, r.Header.Get(tenantHeader))
		if didInject {
			logger.Debug("injected organization_id from X-Tenant-Id header")
		}

		opaReq, err := http.NewRequestWithContext(r.Context(), r.Method, opaURL, bytes.NewReader(mutated))
		if err != nil {
			logger.Error("failed to create request", "error", err)
			http.Error(w, `{"error":"internal"}`, http.StatusBadGateway)
			return
		}
		opaReq.Header = r.Header.Clone()
		// Reset Content-Length so net/http picks the new (possibly
		// larger) body length from bytes.Reader. Leaving the original
		// header in place leads OPA to read only the prefix bytes
		// and reject the body as malformed JSON.
		opaReq.ContentLength = int64(len(mutated))
		opaReq.Header.Set("Content-Length", "")
		// Strip the inbound X-Tenant-Id from the OPA-bound request:
		// rego reads `input.organization_id`, not a header, and an
		// untrusted header echoed onward only widens the attack
		// surface.
		opaReq.Header.Del(tenantHeader)

		resp, err := http.DefaultClient.Do(opaReq)
		if err != nil {
			logger.Error("OPA request failed", "error", err)
			http.Error(w, `{"error":"opa unreachable"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Error("failed to read OPA response", "error", err)
			http.Error(w, `{"error":"bad gateway"}`, http.StatusBadGateway)
			return
		}

		// Accept two shapes for /v1/data/rbac/* responses:
		//   1. { "result": true|false }                                  -> legacy /allow
		//   2. { "result": { "allow": bool, "groups": [...] } }          -> /decision
		// The /decision shape lets the proxy inject X-User-Groups from
		// server-side trusted data (OPA's data.bindings.group_membership
		// fed by OPAL from Redis) without exposing Kratos metadata_admin
		// through /sessions/whoami.
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			logger.Error("failed to parse OPA response", "error", err, "body", string(body))
			http.Error(w, `{"error":"bad gateway"}`, http.StatusBadGateway)
			return
		}

		allowed := false
		// Oathkeeper's remote_json authorizer accepts only HTTP 200
		// (allow) or HTTP 403 (deny). Anything else is treated as an
		// internal error and surfaces as 500 to the caller — including
		// codes like 404 that one might be tempted to use to signal
		// "route_map miss". Keep deny at 403 unconditionally and let
		// the rego's decision.reason ride along as informational
		// telemetry (logged below, also reachable for upstream
		// services through forward_response_headers_to_upstream if
		// they want to differentiate).
		var reason string
		var rich struct {
			Allow         bool     `json:"allow"`
			Groups        []string `json:"groups"`
			Organizations []string `json:"organizations"`
			Reason        string   `json:"reason"`
		}
		if err := json.Unmarshal(envelope.Result, &rich); err == nil && len(envelope.Result) > 0 && envelope.Result[0] == '{' {
			allowed = rich.Allow
			reason = rich.Reason
			// Always set the headers (empty array when no groups /
			// organizations) so the upstream sees a deterministic
			// value via oathkeeper's forward_response_headers_to_upstream.
			groupsJSON, _ := json.Marshal(rich.Groups)
			if rich.Groups == nil {
				groupsJSON = []byte("[]")
			}
			w.Header().Set("X-User-Groups", string(groupsJSON))

			orgsJSON, _ := json.Marshal(rich.Organizations)
			if rich.Organizations == nil {
				orgsJSON = []byte("[]")
			}
			w.Header().Set("X-User-Organizations", string(orgsJSON))

			// Emit the reason as an informational header. Stays a 403
			// either way; upstreams that wire forward_response_headers
			// can render different copy for not_found / forbidden /
			// forbidden_org.
			if reason != "" {
				w.Header().Set("X-Authz-Reason", reason)
			}
		} else {
			var b bool
			if err := json.Unmarshal(envelope.Result, &b); err != nil {
				logger.Error("failed to parse OPA result", "error", err, "body", string(body))
				http.Error(w, `{"error":"bad gateway"}`, http.StatusBadGateway)
				return
			}
			allowed = b
		}

		w.Header().Set("Content-Type", "application/json")
		if allowed {
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		} else {
			logger.Info("access denied", "path", r.URL.Path, "reason", reason)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
		}
	})

	return mux
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
