package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersCSP(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	get := func(path string) http.Header {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Header()
	}

	for _, path := range []string{"/", "/saml/sso", "/v1/me"} {
		if got := get(path).Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
			t.Errorf("%s: enforced CSP = %q, want frame-ancestors only", path, got)
		}
	}

	ro := get("/").Get("Content-Security-Policy-Report-Only")
	for _, want := range []string{"script-src 'self'", "object-src 'none'", "base-uri 'none'", "report-uri /csp-report"} {
		if !strings.Contains(ro, want) {
			t.Errorf("report-only CSP %q is missing %q", ro, want)
		}
	}
	if strings.Contains(ro, "unsafe-inline") || strings.Contains(ro, "unsafe-eval") {
		t.Errorf("report-only CSP must not allow inline or eval: %q", ro)
	}
	if got := get("/saml/sso").Get("Content-Security-Policy-Report-Only"); got != "" {
		t.Errorf("SAML pages submit inline and must not get the strict policy, got %q", got)
	}
}

func TestCSPReportIsLoggedAndAccepted(t *testing.T) {
	rec := httptest.NewRecorder()
	cspReport(rec, httptest.NewRequest(http.MethodPost, "/csp-report", strings.NewReader(`{"csp-report":{}}`)))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
}
