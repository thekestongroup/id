package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// The message centre: announcements from Keston. TKG Admins post and edit
// them; admins of the targeted organisations read them (read and archived
// are each admin's own).

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (a *API) messageRoutes(r chi.Router) {
	r.With(needAdmin).Get("/messages", a.listMessages)
	r.With(needAdmin).Post("/messages/{id}/{action:read|unread|archive|unarchive}", a.setMessageState)
	r.With(needTKG).Get("/messages/all", a.listAllMessages)
	r.With(needTKG).Post("/messages", a.postMessage)
	r.With(needTKG).Put("/messages/{id}", a.putMessage)
	r.With(needTKG).Delete("/messages/{id}", a.deleteMessage)
}

type messagesJSON struct {
	Messages []store.UserMessage `json:"messages"`
	// Unread, not archived: the badge.
	Unread int `json:"unread"`
	// Unread "action required" ones, for the dashboard.
	ActionRequired []store.UserMessage `json:"actionRequired"`
	CanPost        bool                `json:"canPost"`
}

// GET /messages: what reaches the caller's organisation.
func (a *API) listMessages(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	list, err := a.store.MessagesFor(r.Context(), u.OrganisationID, u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := messagesJSON{Messages: []store.UserMessage{}, ActionRequired: []store.UserMessage{}, CanPost: u.PlatformAdmin}
	for _, m := range list {
		out.Messages = append(out.Messages, m)
		if !m.Read && !m.Archived {
			out.Unread++
			if m.Category == "action_required" {
				out.ActionRequired = append(out.ActionRequired, m)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /messages/all: everything posted, with who it is for (TKG Admins).
func (a *API) listAllMessages(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.AllMessages(r.Context())
	if err != nil {
		serverError(w, r, err)
		return
	}
	if list == nil {
		list = []store.Message{}
	}
	writeJSON(w, http.StatusOK, list)
}

// POST /messages/{id}/read|unread|archive|unarchive
func (a *API) setMessageState(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	id := chi.URLParam(r, "id")
	ok, err := false, error(nil)
	if uuidPattern.MatchString(id) {
		ok, err = a.store.MessageReaches(r.Context(), id, u.OrganisationID)
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "That message doesn't exist.")
		return
	}
	yes, no := true, false
	var read, archived *bool
	switch chi.URLParam(r, "action") {
	case "read":
		read = &yes
	case "unread":
		read = &no
	case "archive":
		archived, read = &yes, &yes
	case "unarchive":
		archived = &no
	}
	if err := a.store.SetMessageState(r.Context(), id, u.ID, read, archived); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type messageBody struct {
	Title            string   `json:"title"`
	Body             string   `json:"body"`
	Category         string   `json:"category"`
	ActionBy         string   `json:"actionBy"` // YYYY-MM-DD or empty
	AllOrganisations bool     `json:"allOrganisations"`
	OrganisationIDs  []string `json:"organisationIds"`
}

func (a *API) messageFromBody(w http.ResponseWriter, r *http.Request) (store.Message, bool) {
	var body messageBody
	var m store.Message
	if !decode(w, r, &body) {
		return m, false
	}
	title, ok := cleanText(body.Title, 150)
	if !ok {
		writeFieldError(w, "title", "Give the message a title (up to 150 characters).")
		return m, false
	}
	text, ok := cleanText(body.Body, 10000)
	if !ok {
		writeFieldError(w, "body", "Write the message (up to 10,000 characters).")
		return m, false
	}
	if !slices.Contains(store.MessageCategories, body.Category) {
		writeFieldError(w, "category", "Choose a category.")
		return m, false
	}
	var actionBy *time.Time
	if body.ActionBy != "" {
		t, err := time.Parse(time.DateOnly, body.ActionBy)
		if err != nil {
			writeFieldError(w, "actionBy", "Use a date like 2026-12-31.")
			return m, false
		}
		actionBy = &t
	}
	ids := []string{}
	if !body.AllOrganisations {
		ids = slices.Compact(slices.Sorted(slices.Values(body.OrganisationIDs)))
		if len(ids) == 0 {
			writeFieldError(w, "organisationIds", "Choose who it is for.")
			return m, false
		}
		exist, err := a.store.OrganisationsExist(r.Context(), ids)
		if err != nil {
			writeFieldError(w, "organisationIds", "Choose who it is for.")
			return m, false
		}
		if !exist {
			writeFieldError(w, "organisationIds", "One of those organisations doesn't exist.")
			return m, false
		}
	}
	return store.Message{Title: title, Body: text, Category: body.Category, ActionBy: actionBy,
		AllOrganisations: body.AllOrganisations, OrganisationIDs: ids}, true
}

func audience(m *store.Message) string {
	if m.AllOrganisations {
		return "All organisations"
	}
	return strings.Join(m.OrganisationIDs, ", ")
}

// POST /messages: post, audit it and put it in the bell of the targeted
// organisations' global admins.
func (a *API) postMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := a.messageFromBody(w, r)
	if !ok {
		return
	}
	created, err := a.store.CreateMessage(r.Context(), caller(r), m)
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("message posted", "message", created.ID, "by", caller(r).ID)
	a.auditPlatform(r, store.ActionMessagePosted, store.TargetMessage, created.ID, created.Title,
		"Category: "+created.Category+"; for: "+audience(created))
	if ids, err := a.store.MessageAudienceAdmins(r.Context(), *created); err != nil {
		slog.Warn("message notifications", "error", err)
	} else if err := a.store.Notify(r.Context(), ids, "info", created.Title, "New message from Keston.", "/message-centre"); err != nil {
		slog.Warn("message notifications", "error", err)
	}
	writeJSON(w, http.StatusCreated, created)
}

// PUT /messages/{id}: edit it (no new notifications).
func (a *API) putMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := a.messageFromBody(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not_found", "That message doesn't exist.")
		return
	}
	updated, err := a.store.UpdateMessage(r.Context(), id, m)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That message doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditPlatform(r, store.ActionMessageUpdated, store.TargetMessage, updated.ID, updated.Title,
		"Category: "+updated.Category+"; for: "+audience(updated))
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) deleteMessage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not_found", "That message doesn't exist.")
		return
	}
	title, err := a.store.DeleteMessage(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That message doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditPlatform(r, store.ActionMessageDeleted, store.TargetMessage, id, title, "")
	w.WriteHeader(http.StatusNoContent)
}
