package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
)

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
		opaReq, err := http.NewRequestWithContext(r.Context(), r.Method, opaURL, r.Body)
		if err != nil {
			logger.Error("failed to create request", "error", err)
			http.Error(w, `{"error":"internal"}`, http.StatusBadGateway)
			return
		}
		opaReq.Header = r.Header.Clone()

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

		var decision struct {
			Result bool `json:"result"`
		}
		if err := json.Unmarshal(body, &decision); err != nil {
			logger.Error("failed to parse OPA response", "error", err, "body", string(body))
			http.Error(w, `{"error":"bad gateway"}`, http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if decision.Result {
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		} else {
			logger.Info("access denied", "path", r.URL.Path)
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
