package adminapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/profile"
	"github.com/thekestongroup/id/internal/store"
)

// ── Profiles: built-in fields, manager, custom attributes ────────────────
//
// An admin with "Edit users" changes anyone's profile (users.go's
// updateUser is for name, email and role). People change their own through
// Keston ID's account pages, as far as the organisation allows (settings).
// Custom attributes are defined under Settings → User attributes.

// personRef is a user shown by name (a manager, someone's report).
type personRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	JobTitle string `json:"jobTitle,omitempty"`
}

// profileJSON is a user's profile as the API shows it.
type profileJSON struct {
	profile.Fields
	Manager *personRef `json:"manager"`
	// Custom attribute values by key (string, number or bool).
	Attributes map[string]any `json:"attributes"`
}

func attributesJSON(vals map[string]profile.Value) map[string]any {
	out := make(map[string]any, len(vals))
	for k, v := range vals {
		out[k] = v.JSON()
	}
	return out
}

// profileView: names are the users of the organisation by ID (for the manager).
func profileView(f profile.Fields, vals map[string]profile.Value, names map[string]*store.User) profileJSON {
	v := profileJSON{Fields: f, Attributes: attributesJSON(vals)}
	if m := names[f.ManagerID]; m != nil {
		v.Manager = &personRef{ID: m.ID, Name: m.Name, Email: m.Email}
	} else {
		v.ManagerID = ""
	}
	return v
}

func (a *API) fullProfile(r *http.Request, u *store.User) (profileJSON, error) {
	ctx := r.Context()
	f, err := a.store.ProfileOf(ctx, u.ID)
	if err != nil {
		return profileJSON{}, err
	}
	vals, err := a.store.AttributeValues(ctx, u.ID)
	if err != nil {
		return profileJSON{}, err
	}
	names := map[string]*store.User{}
	if f.ManagerID != "" {
		if name, email, err := a.store.NameOf(ctx, u.OrganisationID, f.ManagerID); err == nil {
			names[f.ManagerID] = &store.User{ID: f.ManagerID, Name: name, Email: email}
		} else if !errors.Is(err, store.ErrNotFound) {
			return profileJSON{}, err
		}
	}
	return profileView(f, vals, names), nil
}

// parsedProfile is what a request asks to change.
type parsedProfile struct {
	fields profile.Fields
	// By attribute ID (nil: clear).
	values map[string]*profile.Value
	byKey  map[string]*profile.Value
}

// parseProfile applies body (the built-in fields by JSON name, "managerEmail"
// as an alternative to managerId, and "attributes": {key: value}) on top of
// cur and checks it all. A problem with one field is a *profile.FieldError.
func (a *API) parseProfile(r *http.Request, org *store.Organisation, defs []store.AttributeDef, cur profile.Fields,
	body map[string]json.RawMessage) (*parsedProfile, error) {
	ctx := r.Context()
	if raw, ok := body["managerEmail"]; ok {
		var s *string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, &profile.FieldError{Field: "managerId", Message: "Enter their manager's email"}
		}
		id := json.RawMessage("null")
		if s != nil && strings.TrimSpace(*s) != "" {
			email := strings.ToLower(strings.TrimSpace(*s))
			if !strings.Contains(email, "@") {
				email += "@" + org.Domain
			}
			m, err := a.store.UserByEmail(ctx, email)
			if err != nil || m.OrganisationID != org.ID || m.Status == "deleted" {
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					return nil, err
				}
				return nil, &profile.FieldError{Field: "managerId", Message: "No one in your organisation has the email " + email}
			}
			id, _ = json.Marshal(m.ID)
		}
		body = maps2(body)
		body["managerId"] = id
	}
	f, err := cur.Patch(body, nil)
	if err != nil {
		return nil, err
	}
	if f.ManagerID != "" && f.ManagerID != cur.ManagerID {
		if _, _, err := a.store.NameOf(ctx, org.ID, f.ManagerID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, &profile.FieldError{Field: "managerId", Message: "Choose someone in your organisation"}
			}
			return nil, err
		}
	}
	p := &parsedProfile{fields: f, values: map[string]*profile.Value{}, byKey: map[string]*profile.Value{}}
	if raw, ok := body["attributes"]; ok && string(raw) != "null" {
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(raw, &attrs); err != nil {
			return nil, &profile.FieldError{Field: "attributes", Message: "Couldn't read the attributes"}
		}
		for key, rawVal := range attrs {
			i := slices.IndexFunc(defs, func(d store.AttributeDef) bool { return d.Key == key })
			if i < 0 {
				return nil, &profile.FieldError{Field: "attributes." + key, Message: "There's no attribute with the key " + key}
			}
			d := defs[i]
			v, err := profile.ParseValue(d.Type, d.Choices, rawVal)
			if err != nil {
				return nil, &profile.FieldError{Field: "attributes." + key, Message: err.Error()}
			}
			p.values[d.ID], p.byKey[key] = v, v
		}
	}
	return p, nil
}

func maps2(m map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// profileProblem writes a *profile.FieldError (or a store error about the
// manager) as a field error and says whether it was one.
func profileProblem(w http.ResponseWriter, err error) bool {
	var fe *profile.FieldError
	switch {
	case errors.As(err, &fe):
		writeFieldError(w, fe.Field, fe.Message)
	case errors.Is(err, store.ErrManagerCycle):
		writeFieldError(w, "managerId", "That would make a loop: they already manage this person, directly or through others.")
	case errors.Is(err, store.ErrManagerInvalid):
		writeFieldError(w, "managerId", "Choose someone else in your organisation. People can't manage themselves.")
	default:
		return false
	}
	return true
}

var fieldLabels = map[string]string{"jobTitle": "Job title", "department": "Department", "office": "Office",
	"phone": "Phone", "mobile": "Mobile", "employeeId": "Employee ID", "managerId": "Manager", "startDate": "Start date"}

// profileChanges describes what changed, for the audit log.
func (a *API) profileChanges(r *http.Request, orgID string, defs []store.AttributeDef, before, after profile.Fields,
	beforeVals map[string]profile.Value, p *parsedProfile) []string {
	var out []string
	for _, key := range profile.FieldKeys {
		b, n := before.Get(key), after.Get(key)
		if key == "managerId" {
			b, n = a.userLabel(r, orgID, b), a.userLabel(r, orgID, n)
		}
		out = append(out, change(fieldLabels[key], b, n))
	}
	for _, d := range defs {
		v, ok := p.values[d.ID]
		if !ok {
			continue
		}
		n := ""
		if v != nil {
			n = v.String()
		}
		b := ""
		if old, had := beforeVals[d.Key]; had {
			b = old.String()
		}
		out = append(out, change(d.Label, b, n))
	}
	return out
}

func (a *API) userLabel(r *http.Request, orgID, id string) string {
	if id == "" {
		return ""
	}
	if name, _, err := a.store.NameOf(r.Context(), orgID, id); err == nil {
		return name
	}
	return "someone"
}

// PUT …/users/{id}/profile {jobTitle?, department?, office?, phone?, mobile?,
// employeeId?, managerId?, startDate?, attributes?: {key: value}}: changes
// what's given (null or "" clears a field). Admins can always change these,
// whatever people may change themselves.
func (a *API) putUserProfile(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	var body map[string]json.RawMessage
	if !decode(w, r, &body) {
		return
	}
	ctx := r.Context()
	org := organisation(r)
	defs, err := a.store.AttributeDefs(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	cur, err := a.store.ProfileOf(ctx, u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	curVals, err := a.store.AttributeValues(ctx, u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	p, err := a.parseProfile(r, org, defs, cur, body)
	if err != nil {
		if !profileProblem(w, err) {
			serverError(w, r, err)
		}
		return
	}
	if err := a.store.SaveProfile(ctx, org.ID, u.ID, p.fields, p.values); err != nil {
		if !profileProblem(w, err) {
			serverError(w, r, err)
		}
		return
	}
	slog.Info("profile updated", "user", u.ID, "by", caller(r).ID)
	if s := summary(a.profileChanges(r, org.ID, defs, cur, p.fields, curVals, p)...); s != "" {
		a.audit(r, store.ActionUserUpdated, aboutUser(u), s)
	}
	v, err := a.fullProfile(r, u)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// saveNewProfile stores the profile of someone just created (body already
// checked by parseProfile).
func (a *API) saveNewProfile(r *http.Request, u *store.User, p *parsedProfile) error {
	if p == nil {
		return nil
	}
	if err := a.store.SaveProfile(r.Context(), u.OrganisationID, u.ID, p.fields, p.values); err != nil {
		return err
	}
	return nil
}

// profileSummary is the audit-log text for a profile given at creation.
func (a *API) profileSummary(r *http.Request, orgID string, defs []store.AttributeDef, p *parsedProfile) string {
	if p == nil {
		return ""
	}
	return summary(a.profileChanges(r, orgID, defs, profile.Fields{}, p.fields, nil, p)...)
}

// ── GET …/users/{id}/profile pieces used by getUser ──────────────────────

// reportsOf: people who report to the user.
func (a *API) reportsOf(r *http.Request, u *store.User) ([]personRef, error) {
	reports, err := a.store.DirectReports(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]personRef, len(reports))
	for i, x := range reports {
		out[i] = personRef{ID: x.ID, Name: x.Name, Email: x.Email, JobTitle: x.JobTitle}
	}
	return out, nil
}

// ── User attributes (Settings → User attributes) ─────────────────────────

// GET …/user-attributes: the organisation's custom attributes.
func (a *API) listAttributes(w http.ResponseWriter, r *http.Request) {
	defs, err := a.store.AttributeDefs(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, defs)
}

type attributeBody struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`
	Choices []string `json:"choices"`
}

func attributeSummary(d *store.AttributeDef) string {
	s := d.Label + " (" + d.Key + ", " + d.Type + ")"
	if d.Type == profile.TypeChoice {
		s += ": " + strings.Join(d.Choices, ", ")
	}
	return s
}

// POST …/user-attributes {key, label, type, choices?}.
func (a *API) createAttribute(w http.ResponseWriter, r *http.Request) {
	var body attributeBody
	if !decode(w, r, &body) {
		return
	}
	body.Key, body.Label = strings.TrimSpace(body.Key), strings.TrimSpace(body.Label)
	if err := profile.ValidAttributeKey(body.Key); err != nil {
		writeFieldError(w, "key", err.Error())
		return
	}
	if !a.checkAttributeLabel(w, body.Label) {
		return
	}
	if !slices.Contains(profile.AttributeTypes, body.Type) {
		writeFieldError(w, "type", "Choose text, number, date, yes/no or choice list")
		return
	}
	d := store.AttributeDef{Key: body.Key, Label: body.Label, Type: body.Type, Choices: []string{}}
	if body.Type == profile.TypeChoice {
		c, err := profile.NormaliseChoices(body.Choices)
		if err != nil {
			writeFieldError(w, "choices", err.Error())
			return
		}
		d.Choices = c
	}
	created, err := a.store.CreateAttributeDef(r.Context(), organisation(r).ID, d)
	switch {
	case errors.Is(err, store.ErrAttributeKey):
		writeFieldError(w, "key", "You already have an attribute with that key.")
		return
	case errors.Is(err, store.ErrTooManyAttributes):
		writeFieldError(w, "key", "You can have up to 50 attributes.")
		return
	case err != nil:
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionAttributeCreated, aboutOrg(organisation(r)), attributeSummary(created))
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) checkAttributeLabel(w http.ResponseWriter, label string) bool {
	if label == "" || !profile.ValidText(label, 100) {
		writeFieldError(w, "label", "Enter a name of up to 100 characters")
		return false
	}
	return true
}

// PUT …/user-attributes/{id} {label, choices?}: the key and type can't change.
func (a *API) updateAttribute(w http.ResponseWriter, r *http.Request) {
	var body attributeBody
	if !decode(w, r, &body) {
		return
	}
	org := organisation(r)
	id := chi.URLParam(r, "attributeID")
	defs, err := a.store.AttributeDefs(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	i := slices.IndexFunc(defs, func(d store.AttributeDef) bool { return d.ID == id })
	if i < 0 {
		writeError(w, http.StatusNotFound, "not_found", "That attribute doesn't exist.")
		return
	}
	old := defs[i]
	body.Label = strings.TrimSpace(body.Label)
	if !a.checkAttributeLabel(w, body.Label) {
		return
	}
	choices := old.Choices
	if old.Type == profile.TypeChoice {
		if choices, err = profile.NormaliseChoices(body.Choices); err != nil {
			writeFieldError(w, "choices", err.Error())
			return
		}
	}
	d, err := a.store.UpdateAttributeDef(r.Context(), org.ID, id, body.Label, choices)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That attribute doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionAttributeUpdated, aboutOrg(org), summary(change("Name", old.Label, d.Label),
		change("Choices", strings.Join(old.Choices, ", "), strings.Join(d.Choices, ", ")))+" ("+d.Key+")")
	writeJSON(w, http.StatusOK, d)
}

// DELETE …/user-attributes/{id}: removes it and everyone's value for it.
func (a *API) deleteAttribute(w http.ResponseWriter, r *http.Request) {
	org := organisation(r)
	id := chi.URLParam(r, "attributeID")
	if !store.IsUUID(id) {
		writeError(w, http.StatusNotFound, "not_found", "That attribute doesn't exist.")
		return
	}
	d, err := a.store.DeleteAttributeDef(r.Context(), org.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That attribute doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionAttributeDeleted, aboutOrg(org), attributeSummary(d))
	w.WriteHeader(http.StatusNoContent)
}
