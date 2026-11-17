package adminapi

// Keston-wide apps: apps every organisation sees, which TKG Admins (in The
// Keston Group) create, change and retire here. Others are registered from
// deploy/clients.json by `keston-id clients sync` and are read-only
// ("Managed by deployment"); sync never overwrites the ones made here.
//
//	GET    …/keston-apps                  every Keston-wide app, retired ones too
//	POST   …/keston-apps                  add one; a web app's secret is returned once
//	GET    …/keston-apps/{clientID}
//	PATCH  …/keston-apps/{clientID}       change it (not its type)
//	POST   …/keston-apps/{clientID}/secret   a new secret, returned once
//	POST   …/keston-apps/{clientID}/retire   no longer shown or signed in to
//	POST   …/keston-apps/{clientID}/restore

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

func (a *API) kestonAppRoutes(r chi.Router) {
	r.Use(a.requireKestonAppAdmin)
	r.Get("/", a.listKestonApps)
	r.Post("/", a.createKestonApp)
	r.Get("/{clientID}", a.getKestonApp)
	r.Patch("/{clientID}", a.updateKestonApp)
	r.Post("/{clientID}/secret", a.newKestonAppSecret)
	r.Post("/{clientID}/retire", a.retireKestonApp)
	r.Post("/{clientID}/restore", a.restoreKestonApp)
}

// canManageKestonApps: a TKG Admin, in The Keston Group.
func (a *API) canManageKestonApps(r *http.Request) bool {
	org := organisation(r)
	u := caller(r)
	return org.IsPlatform && u.PlatformAdmin && u.OrganisationID == org.ID && !u.IsSupport()
}

func (a *API) requireKestonAppAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.canManageKestonApps(r) {
			writeError(w, http.StatusForbidden, "no_permission", "Only TKG Admins can manage Keston-wide apps.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type kestonAppJSON struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	Publisher              string   `json:"publisher"`
	Type                   string   `json:"type"`
	LogoURL                string   `json:"logoUrl"`
	PrivacyURL             string   `json:"privacyUrl"`
	TermsURL               string   `json:"termsUrl"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	Scopes                 []string `json:"scopes"`
	ManagedBy              string   `json:"managedBy"`
	Retired                bool     `json:"retired"`
	HasSecret              bool     `json:"hasSecret"`
	Issuer                 string   `json:"issuer"`
	DiscoveryURL           string   `json:"discoveryUrl"`
}

func (a *API) kestonAppView(c *store.Client) kestonAppJSON {
	typ := typeWeb
	if c.Native || c.SecretHash == nil {
		typ = typeNative
	}
	return kestonAppJSON{ID: c.ID, Name: c.Name, Description: c.Description, Publisher: c.Publisher, Type: typ,
		LogoURL: c.LogoURL, PrivacyURL: c.PrivacyURL, TermsURL: c.TermsURL, RedirectURIs: c.RedirectURIs,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs, Scopes: append(slices.Clone(c.RequiredScopes), c.OptionalScopes...),
		ManagedBy: c.ManagedBy, Retired: c.RetiredAt != nil, HasSecret: c.SecretHash != nil, Issuer: a.issuer,
		DiscoveryURL: a.issuer + "/.well-known/openid-configuration"}
}

func (a *API) listKestonApps(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.KestonClients(r.Context())
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := []kestonAppJSON{}
	for i := range list {
		out = append(out, a.kestonAppView(&list[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) kestonApp(w http.ResponseWriter, r *http.Request) *store.Client {
	c, err := a.store.KestonClient(r.Context(), chi.URLParam(r, "clientID"))
	if err != nil || c.ID == ClientID {
		writeError(w, http.StatusNotFound, "not_found", "That app doesn't exist.")
		return nil
	}
	return c
}

// editableKestonApp: the app, unless the deployment manages it (409).
func (a *API) editableKestonApp(w http.ResponseWriter, r *http.Request) *store.Client {
	c := a.kestonApp(w, r)
	if c != nil && c.ManagedBy != store.ManagedByAdmin {
		writeError(w, http.StatusConflict, "managed_by_deployment",
			c.Name+" is managed by the deployment (deploy/clients.json), so it can't be changed here.")
		return nil
	}
	return c
}

func (a *API) getKestonApp(w http.ResponseWriter, r *http.Request) {
	if c := a.kestonApp(w, r); c != nil {
		writeJSON(w, http.StatusOK, map[string]any{"app": a.kestonAppView(c)})
	}
}

type kestonAppBody struct {
	Name                   *string   `json:"name"`
	Description            *string   `json:"description"`
	Type                   *string   `json:"type"`
	LogoURL                *string   `json:"logoUrl"`
	PrivacyURL             *string   `json:"privacyUrl"`
	TermsURL               *string   `json:"termsUrl"`
	RedirectURIs           *[]string `json:"redirectUris"`
	PostLogoutRedirectURIs *[]string `json:"postLogoutRedirectUris"`
	Scopes                 *[]string `json:"scopes"`
}

func (a *API) createKestonApp(w http.ResponseWriter, r *http.Request) {
	var body kestonAppBody
	if !decode(w, r, &body) {
		return
	}
	c := &store.Client{ID: store.NewClientID(), Publisher: store.KestonPublisher, Protocol: "oidc",
		RequiredScopes: []string{"openid"}, RedirectURIs: []string{}, PostLogoutRedirectURIs: []string{}}
	switch deref(body.Type) {
	case typeWeb:
	case typeNative:
		c.Native = true
	default:
		writeFieldError(w, "type", "Choose the type of app")
		return
	}
	if body.Name == nil {
		body.Name = new(string)
	}
	if body.RedirectURIs == nil {
		body.RedirectURIs = &[]string{}
	}
	a.saveKestonApp(w, r, c, &body, true)
}

func (a *API) updateKestonApp(w http.ResponseWriter, r *http.Request) {
	c := a.editableKestonApp(w, r)
	if c == nil {
		return
	}
	var body kestonAppBody
	if !decode(w, r, &body) {
		return
	}
	a.saveKestonApp(w, r, c, &body, false)
}

func (a *API) saveKestonApp(w http.ResponseWriter, r *http.Request, c *store.Client, body *kestonAppBody, creating bool) {
	ctx := r.Context()
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" || len(name) > 100 {
			writeFieldError(w, "name", "Enter the app's name (up to 100 characters)")
			return
		}
		c.Name = name
	}
	if body.Description != nil {
		d := strings.TrimSpace(*body.Description)
		if len(d) > 500 {
			writeFieldError(w, "description", "Describe the app in up to 500 characters")
			return
		}
		c.Description = d
	}
	for _, f := range []struct {
		field  string
		in     *string
		target *string
		label  string
	}{
		{"logoUrl", body.LogoURL, &c.LogoURL, "logo"},
		{"privacyUrl", body.PrivacyURL, &c.PrivacyURL, "privacy policy"},
		{"termsUrl", body.TermsURL, &c.TermsURL, "terms"},
	} {
		if f.in == nil {
			continue
		}
		v := strings.TrimSpace(*f.in)
		if v != "" && !httpsURL(v) {
			writeFieldError(w, f.field, "Enter an https:// link to the app's "+f.label+", or leave it empty")
			return
		}
		*f.target = v
	}
	if body.RedirectURIs != nil {
		uris, bad := cleanRedirects(*body.RedirectURIs, c.Native)
		if bad != "" || len(uris) == 0 {
			writeFieldError(w, "redirectUris", redirectHelp(bad, c.Native))
			return
		}
		c.RedirectURIs = uris
	}
	if body.PostLogoutRedirectURIs != nil {
		uris, bad := cleanRedirects(*body.PostLogoutRedirectURIs, c.Native)
		if bad != "" {
			writeFieldError(w, "postLogoutRedirectUris", redirectHelp(bad, c.Native))
			return
		}
		c.PostLogoutRedirectURIs = uris
	}
	if body.Scopes != nil {
		scopes := []string{"openid"}
		for _, s := range *body.Scopes {
			if !slices.Contains(ownAppScopes, s) {
				writeFieldError(w, "scopes", "Choose from profile, email, phone, keston.profile and offline_access")
				return
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		c.RequiredScopes = scopes
	}

	var newSecret string
	if creating {
		if err := a.store.CreateKestonClient(ctx, c); err != nil {
			serverError(w, r, err)
			return
		}
		if !c.Native {
			var err error
			if newSecret, err = a.store.SetKestonClientSecret(ctx, c.ID); err != nil {
				serverError(w, r, err)
				return
			}
		}
		a.audit(r, store.ActionKestonAppCreated, aboutApp(c), kestonTypeLabel(c))
	} else {
		if err := a.store.UpdateKestonClient(ctx, c); err != nil {
			serverError(w, r, err)
			return
		}
		a.audit(r, store.ActionKestonAppUpdated, aboutApp(c), "")
	}
	slog.Info("keston app saved", "app", c.ID, "creating", creating, "by", caller(r).ID)
	saved, err := a.store.KestonClient(ctx, c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := map[string]any{"app": a.kestonAppView(saved)}
	status := http.StatusOK
	if creating {
		status = http.StatusCreated
	}
	if newSecret != "" {
		out["clientSecret"] = newSecret
	}
	writeJSON(w, status, out)
}

func kestonTypeLabel(c *store.Client) string {
	if c.Native {
		return "Single-page or mobile app"
	}
	return "Web app"
}

// POST …/keston-apps/{clientID}/secret: a new secret, shown once (web apps).
func (a *API) newKestonAppSecret(w http.ResponseWriter, r *http.Request) {
	c := a.editableKestonApp(w, r)
	if c == nil {
		return
	}
	if c.Native {
		writeError(w, http.StatusConflict, "no_secret", "Only web apps have a secret.")
		return
	}
	value, err := a.store.SetKestonClientSecret(r.Context(), c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("keston app secret changed", "app", c.ID, "by", caller(r).ID)
	a.audit(r, store.ActionKestonAppSecret, aboutApp(c), "The old secret stopped working")
	c, _ = a.store.KestonClient(r.Context(), c.ID)
	writeJSON(w, http.StatusOK, map[string]any{"app": a.kestonAppView(c), "clientSecret": value})
}

func (a *API) retireKestonApp(w http.ResponseWriter, r *http.Request)  { a.setRetired(w, r, true) }
func (a *API) restoreKestonApp(w http.ResponseWriter, r *http.Request) { a.setRetired(w, r, false) }

func (a *API) setRetired(w http.ResponseWriter, r *http.Request, retire bool) {
	c := a.editableKestonApp(w, r)
	if c == nil {
		return
	}
	if err := a.store.RetireKestonClient(r.Context(), c.ID, retire); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That app doesn't exist.")
		return
	} else if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("keston app retired or restored", "app", c.ID, "retired", retire, "by", caller(r).ID)
	if retire {
		a.audit(r, store.ActionKestonAppRetired, aboutApp(c), "No longer shown or signed in to")
	} else {
		a.audit(r, store.ActionKestonAppRestored, aboutApp(c), "")
	}
	c, _ = a.store.KestonClient(r.Context(), c.ID)
	writeJSON(w, http.StatusOK, map[string]any{"app": a.kestonAppView(c)})
}
