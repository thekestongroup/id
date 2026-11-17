package api

import (
	"errors"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/clientip"
	"github.com/thekestongroup/id/internal/store"
)

// App requests, from the person's side (store/app_requests.go):
//
//	GET    /v1/me/requestable-apps       apps their organisation has that they can't use yet
//	GET    /v1/me/app-requests           their requests and how they went
//	POST   /v1/me/app-requests           {clientId, reason}
//	DELETE /v1/me/app-requests/{id}      withdraw a pending one
//	POST   /v1/me/app-requests/seen      they've seen the outcomes

func (a *API) appRequestRoutes(r chi.Router) {
	r.Get("/requestable-apps", a.requestableApps)
	r.Get("/app-requests", a.myAppRequests)
	r.Post("/app-requests", a.createAppRequest)
	r.Post("/app-requests/seen", a.appRequestsSeen)
	r.Delete("/app-requests/{requestID}", a.cancelAppRequest)
}

func (a *API) requestableApps(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	list, err := a.store.RequestableApps(r.Context(), cur.user, clientip.From(r))
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := make([]clientView, 0, len(list))
	for i := range list {
		out = append(out, viewClient(&list[i], first(list[i].RedirectURIs)))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) myAppRequests(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.MyAppRequests(r.Context(), from(r).user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createAppRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID string `json:"clientId"`
		Reason   string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	req, err := a.store.CreateAppRequest(r.Context(), from(r).user, body.ClientID, body.Reason, clientip.From(r))
	switch {
	case errors.Is(err, store.ErrReasonInvalid):
		writeFieldError(w, "reason", "Tell them why you need it, in up to 500 characters")
	case errors.Is(err, store.ErrRequestsOff):
		writeError(w, http.StatusForbidden, "requests_off", "Your organisation doesn't take requests for apps.")
	case errors.Is(err, store.ErrNotRequestable):
		writeError(w, http.StatusNotFound, "not_requestable", "You can't ask for that app.")
	case errors.Is(err, store.ErrAlreadyHasAccess):
		writeError(w, http.StatusConflict, "already_has_access", "You can already use that app.")
	case errors.Is(err, store.ErrPending):
		writeError(w, http.StatusConflict, "already_pending", "You've already asked for that app. Wait to hear back.")
	case errors.Is(err, store.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", "You've asked for several apps today. Try again tomorrow.")
	case err != nil:
		serverError(w, r, err)
	default:
		writeJSON(w, http.StatusCreated, req)
	}
}

func (a *API) cancelAppRequest(w http.ResponseWriter, r *http.Request) {
	err := a.store.CancelAppRequest(r.Context(), from(r).user, chi.URLParam(r, "requestID"), clientip.From(r))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That request doesn't exist, or has been decided.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) appRequestsSeen(w http.ResponseWriter, r *http.Request) {
	if err := a.store.MarkAppRequestsSeen(r.Context(), from(r).user.ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeAppRefused: when sign-in to an app is refused (turned off for them, or
// no licence) and they may ask for it, say so, so the error page can offer
// "Request access". It reports whether it wrote the response.
func (a *API) writeAppRefused(w http.ResponseWriter, r *http.Request, cur *current, authRequestID, msg string) bool {
	if authRequestID == "" {
		return false
	}
	ar, err := a.store.AuthRequestByID(r.Context(), authRequestID)
	if err != nil || !a.store.CanRequest(r.Context(), cur.user, ar.ClientID, clientip.From(r)) {
		return false
	}
	client, err := a.store.ClientByID(r.Context(), ar.ClientID)
	if err != nil {
		return false
	}
	pending := false
	if list, err := a.store.MyAppRequests(r.Context(), cur.user.ID); err == nil {
		pending = slices.ContainsFunc(list, func(q store.AppRequest) bool {
			return q.ClientID == client.ID && q.Status == store.RequestPending
		})
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"error": "app_refused", "message": msg,
		"clientId": client.ID, "clientName": client.Name, "canRequest": true, "pending": pending})
	return true
}
