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

	for _, path := range []string{"/", "/v1/me"} {
		got := get(path).Get("Content-Security-Policy")
		for _, want := range []string{"script-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "report-uri /csp-report"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: CSP %q is missing %q", path, got, want)
			}
		}
		if strings.Contains(got, "unsafe-inline") || strings.Contains(got, "unsafe-eval") {
			t.Errorf("%s: CSP must not allow inline or eval: %q", path, got)
		}
	}
	// SAML pages submit inline: they only get the framing rule.
	if got := get("/saml/sso").Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("SAML CSP = %q, want frame-ancestors only", got)
	}
}

func TestCSPReportIsLoggedAndAccepted(t *testing.T) {
	rec := httptest.NewRecorder()
	cspReport(rec, httptest.NewRequest(http.MethodPost, "/csp-report", strings.NewReader(`{"csp-report":{}}`)))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
}
