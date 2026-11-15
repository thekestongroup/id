// Package apierr writes errors in the one format every Keston API uses:
//
//	{"error": "not_found", "message": "That user doesn't exist.", "field": "email"}
//
// error is a stable code for programs; message is a sentence people can be
// shown as it is; field (optional) is the request field it's about, for
// showing it next to that field in a form.
package apierr

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Body is an error response.
type Body struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// Write sends an error.
func Write(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, Body{Code: code, Message: message})
}

// Field sends a 422 about one request field.
func Field(w http.ResponseWriter, field, message string) {
	writeJSON(w, http.StatusUnprocessableEntity, Body{Code: "invalid", Message: message, Field: field})
}

// Common errors, worded the same in every API.

func Unauthorized(w http.ResponseWriter) {
	Write(w, http.StatusUnauthorized, "signed_out", "Your session has ended. Sign in again.")
}

func Forbidden(w http.ResponseWriter, message string) {
	if message == "" {
		message = "You don't have permission to do that. Ask one of your global admins."
	}
	Write(w, http.StatusForbidden, "no_permission", message)
}

func NotFound(w http.ResponseWriter, message string) {
	Write(w, http.StatusNotFound, "not_found", message)
}

// Server logs err and sends a 500 without its details.
func Server(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	Write(w, http.StatusInternalServerError, "server_error", "Something went wrong. Try again.")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
