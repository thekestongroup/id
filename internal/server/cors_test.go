package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPICORS(t *testing.T) {
	reached := false
	h := apiCORS([]string{"https://admin.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// A listed site: preflight is answered without reaching the API.
	req := httptest.NewRequest(http.MethodOptions, "/v1/me", nil)
	req.Header.Set("Origin", "https://admin.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || reached {
		t.Fatalf("preflight: %d, reached=%v", rec.Code, reached)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.example.com" {
		t.Errorf("allow-origin: %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("credentials must never be allowed")
	}

	// A real request from the listed site goes through, with the header.
	req = httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Origin", "https://admin.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !reached || rec.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("listed site: request should reach the API with CORS headers")
	}

	// Any other site: passes through with no CORS headers (the browser blocks it).
	reached = false
	req = httptest.NewRequest(http.MethodOptions, "/v1/me", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("unlisted site got CORS headers")
	}
}
