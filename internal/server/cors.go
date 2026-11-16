package server

import (
	"net/http"
	"slices"
)

// apiCORS lets the listed sites (exactly, e.g. https://admin.example.com)
// call the API from a browser: Keston Admin is its own site and talks to
// Keston ID directly, with its access token in the Authorization header.
//
// Cookies are never allowed across sites (no Access-Control-Allow-Credentials),
// so a page on another site can't borrow someone's Keston ID session: only a
// token its own sign-in produced works. A request from a site that isn't
// listed gets no CORS headers, and the browser blocks it.
func apiCORS(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" || !slices.Contains(origins, origin) {
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Origin", origin)
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
