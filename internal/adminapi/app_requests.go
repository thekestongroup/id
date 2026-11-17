package adminapi

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/clientip"
	"github.com/thekestongroup/id/internal/store"
)

// App requests (store/app_requests.go): people ask for apps they can't use;
// admins who set app access or assign licences (and global admins) decide.
//
//	GET  …/app-requests?status=&app=&q=     the list, pending first, with what approving does
//	GET  …/app-requests/count               pending, for the badge
//	POST …/app-requests/{id}/approve        {message?, addToRule?, assignLicence?}
//	POST …/app-requests/{id}/decline        {message?}
//	POST …/app-requests/bulk                {ids, action: approve|decline, message?}
//	GET/PUT …/app-request-settings          {enabled, excluded}: "Let people request apps"

func (a *API) needRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if can(r, store.PermApps) || can(r, store.PermLicences) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusForbidden, "no_permission", "You don't have permission to do that. Ask one of your global admins.")
	})
}

func (a *API) listAppRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	if !slices.Contains([]string{"", store.RequestPending, store.RequestApproved, store.RequestDeclined}, status) {
		writeFieldError(w, "status", "Choose pending, approved or declined")
		return
	}
	list, err := a.store.AppRequestsOf(r.Context(), organisation(r).ID,
		store.RequestFilter{Status: status, ClientID: q.Get("app"), Query: q.Get("q")})
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) appRequestCount(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.PendingAppRequestCount(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"pending": n})
}

// decideRequest: approve or decline one request; "" error means done, else
// the status and message to give.
func (a *API) decideRequest(r *http.Request, id, action, message string, addToRule, assign *bool) (*store.AppRequest, int, string, error) {
	ctx, org, by := r.Context(), organisation(r), caller(r)
	if action == "decline" {
		req, err := a.store.DeclineAppRequest(ctx, org.ID, id, by, message, clientip.From(r))
		return req, 0, "", err
	}
	req, err := a.store.AppRequestByID(ctx, org.ID, id)
	if err != nil {
		return nil, 0, "", err
	}
	if req.Status == store.RequestPending {
		plan, err := a.store.PlanFor(ctx, req)
		if err != nil {
			return nil, 0, "", err
		}
		doRule := plan.AddToRule && (addToRule == nil || *addToRule)
		doLicence := plan.AssignLicence && (assign == nil || *assign)
		if doRule && !can(r, store.PermApps) {
			return nil, http.StatusForbidden, "Approving this changes app access, which needs the permission to set app access. Ask one of your global admins.", errors.New("perm")
		}
		if doLicence && !can(r, store.PermLicences) {
			return nil, http.StatusForbidden, "Approving this assigns a licence, which needs the permission to assign licences. Ask one of your global admins.", errors.New("perm")
		}
	}
	req, err = a.store.ApproveAppRequest(ctx, org.ID, id, by, store.ApproveOptions{AddToRule: addToRule,
		AssignLicence: assign, Message: message, IP: clientip.From(r)})
	return req, 0, "", err
}

// writeRequestError writes the error for a failed decision.
func writeRequestError(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	var noSeats *store.NoSeatsError
	switch {
	case status != 0:
		writeError(w, status, "no_permission", msg)
	case errors.As(err, &noSeats):
		writeError(w, http.StatusConflict, "no_seats", noSeatsMessage(noSeats))
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "That request doesn't exist.")
	case errors.Is(err, store.ErrNotPending):
		writeError(w, http.StatusConflict, "not_pending", "That request has already been decided or withdrawn.")
	case errors.Is(err, store.ErrRequesterGone):
		writeError(w, http.StatusConflict, "requester_gone", "This person can't use apps any more (disabled, deleted or moved). Decline the request.")
	default:
		serverError(w, r, err)
	}
}

func (a *API) decideAppRequest(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "decision")
	var body struct {
		Message       string `json:"message"`
		AddToRule     *bool  `json:"addToRule"`
		AssignLicence *bool  `json:"assignLicence"`
	}
	if err := decodeOptional(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the request.")
		return
	}
	if len(body.Message) > 500 {
		writeFieldError(w, "message", "Keep the message under 500 characters")
		return
	}
	req, status, msg, err := a.decideRequest(r, chi.URLParam(r, "requestID"), action, body.Message, body.AddToRule, body.AssignLicence)
	if err != nil {
		writeRequestError(w, r, status, msg, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// POST …/app-requests/bulk: each request on its own (like the users' bulk
// actions): done, or skipped with the reason.
func (a *API) bulkAppRequests(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs     []string `json:"ids"`
		Action  string   `json:"action"`
		Message string   `json:"message"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Action != "approve" && body.Action != "decline" {
		writeFieldError(w, "action", "Choose approve or decline")
		return
	}
	if len(body.IDs) == 0 || len(body.IDs) > maxBulk || len(body.Message) > 500 {
		writeError(w, http.StatusBadRequest, "bad_request", "Choose between 1 and 500 requests.")
		return
	}
	type result struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		App    string `json:"app"`
		Result string `json:"result"`
		Reason string `json:"reason,omitempty"`
	}
	out := []result{}
	for _, id := range body.IDs {
		res := result{ID: id, Result: "done"}
		if cur, err := a.store.AppRequestByID(r.Context(), organisation(r).ID, id); err == nil {
			res.Name, res.App = cur.UserName, cur.AppName
		}
		_, status, msg, err := a.decideRequest(r, id, body.Action, body.Message, nil, nil)
		if err != nil {
			res.Result = "skipped"
			var noSeats *store.NoSeatsError
			switch {
			case status != 0:
				res.Reason = msg
			case errors.As(err, &noSeats):
				res.Reason = noSeatsMessage(noSeats)
			case errors.Is(err, store.ErrNotFound):
				res.Reason = "That request doesn't exist."
			case errors.Is(err, store.ErrNotPending):
				res.Reason = "Already decided or withdrawn."
			case errors.Is(err, store.ErrRequesterGone):
				res.Reason = "This person can't use apps any more."
			default:
				serverError(w, r, err)
				return
			}
		}
		out = append(out, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (a *API) getRequestSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.store.RequestSettings(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *API) putRequestSettings(w http.ResponseWriter, r *http.Request) {
	var body store.RequestSettings
	if !decode(w, r, &body) {
		return
	}
	summary, err := a.store.SetRequestSettings(r.Context(), organisation(r).ID, body.Enabled, body.Excluded)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "excluded", "Choose from this organisation's apps")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	if summary != "" {
		a.audit(r, store.ActionAppRequestSettings, aboutOrg(organisation(r)), strings.TrimSpace(summary))
	}
	a.getRequestSettings(w, r)
}
