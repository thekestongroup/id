package adminapi

// Own apps: SSO apps an organisation adds itself (Keston Admin → Apps →
// Add an app), with OpenID Connect or SAML. Users with "Set app access".
//
//	GET    …/own-apps                   the organisation's own apps
//	POST   …/own-apps                   add one ({protocol: "oidc"|"saml", …}); an OIDC web app's secret is returned once
//	GET    …/own-apps/{clientID}
//	PATCH  …/own-apps/{clientID}        change it (not its protocol or type)
//	DELETE …/own-apps/{clientID}
//	POST   …/own-apps/{clientID}/secret a new secret (the old one stops working), returned once
//
// They're only for the organisation's users, skip the consent prompt, and
// never get Keston's own claims or audiences (see oidcstore.keston).

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/samlidp"
	"github.com/thekestongroup/id/internal/store"
)

// SetSAML gives the API Keston ID's SAML identity provider, for SAML apps'
// IdP details.
func (a *API) SetSAML(idp *samlidp.IdP) { a.saml = idp }

func (a *API) ownAppRoutes(r chi.Router) {
	r.Get("/", a.listOwnApps)
	r.Post("/", a.createOwnApp)
	r.Get("/{clientID}", a.getOwnApp)
	r.Patch("/{clientID}", a.updateOwnApp)
	r.Delete("/{clientID}", a.deleteOwnApp)
	r.Post("/{clientID}/secret", a.newOwnAppSecret)
}

// The scopes an organisation's OpenID Connect app can ask for.
var ownAppScopes = []string{"openid", "profile", "email", "phone", "keston.profile", "offline_access"}

// App types (OpenID Connect).
const (
	typeWeb    = "web"    // a server-side web app, with a secret
	typeNative = "native" // a single-page or mobile app: PKCE, no secret
)

type ownAppJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
	LogoURL     string `json:"logoUrl"`
	PrivacyURL  string `json:"privacyUrl"`
	TermsURL    string `json:"termsUrl"`
	OIDC        *struct {
		Type                   string   `json:"type"`
		ClientID               string   `json:"clientId"`
		HasSecret              bool     `json:"hasSecret"`
		Issuer                 string   `json:"issuer"`
		DiscoveryURL           string   `json:"discoveryUrl"`
		RedirectURIs           []string `json:"redirectUris"`
		PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
		Scopes                 []string `json:"scopes"`
	} `json:"oidc,omitempty"`
	SAML *struct {
		EntityID    string `json:"entityId"`
		ACSURL      string `json:"acsUrl"`
		MetadataURL string `json:"metadataUrl"`
		// What to give the app: Keston ID's details.
		IdP samlidp.AppInfo `json:"idp"`
	} `json:"saml,omitempty"`
}

func (a *API) ownAppView(ctx context.Context, c *store.Client) (ownAppJSON, error) {
	v := ownAppJSON{ID: c.ID, Name: c.Name, Description: c.Description, Protocol: c.Protocol, LogoURL: c.LogoURL, PrivacyURL: c.PrivacyURL,
		TermsURL: c.TermsURL}
	switch c.Protocol {
	case "saml":
		app, err := a.store.SAMLApp(ctx, c.ID)
		if err != nil {
			return v, err
		}
		info, err := a.saml.Info(ctx, c.ID)
		if err != nil {
			return v, err
		}
		v.SAML = &struct {
			EntityID    string          `json:"entityId"`
			ACSURL      string          `json:"acsUrl"`
			MetadataURL string          `json:"metadataUrl"`
			IdP         samlidp.AppInfo `json:"idp"`
		}{app.EntityID, app.ACSURL, app.MetadataURL, info}
	default:
		typ := typeWeb
		if c.Native {
			typ = typeNative
		}
		v.OIDC = &struct {
			Type                   string   `json:"type"`
			ClientID               string   `json:"clientId"`
			HasSecret              bool     `json:"hasSecret"`
			Issuer                 string   `json:"issuer"`
			DiscoveryURL           string   `json:"discoveryUrl"`
			RedirectURIs           []string `json:"redirectUris"`
			PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
			Scopes                 []string `json:"scopes"`
		}{typ, c.ID, c.SecretHash != nil, a.issuer, a.issuer + "/.well-known/openid-configuration", c.RedirectURIs,
			c.PostLogoutRedirectURIs, c.RequiredScopes}
	}
	return v, nil
}

func (a *API) listOwnApps(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.OrganisationClients(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := []ownAppJSON{}
	for i := range list {
		v, err := a.ownAppView(r.Context(), &list[i])
		if err != nil {
			serverError(w, r, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// ownApp: the organisation's app in the URL, or a 404.
func (a *API) ownApp(w http.ResponseWriter, r *http.Request) *store.Client {
	c, err := a.store.OrganisationClient(r.Context(), organisation(r).ID, chi.URLParam(r, "clientID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "That app doesn't exist.")
		return nil
	}
	return c
}

func (a *API) getOwnApp(w http.ResponseWriter, r *http.Request) {
	c := a.ownApp(w, r)
	if c == nil {
		return
	}
	a.writeOwnApp(w, r, http.StatusOK, c, "")
}

// writeOwnApp: the app, and its new secret when there is one (shown once).
func (a *API) writeOwnApp(w http.ResponseWriter, r *http.Request, status int, c *store.Client, newSecret string) {
	v, err := a.ownAppView(r.Context(), c)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := map[string]any{"app": v}
	if newSecret != "" {
		out["clientSecret"] = newSecret
	}
	writeJSON(w, status, out)
}

type ownAppBody struct {
	Protocol    *string `json:"protocol"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
	LogoURL     *string `json:"logoUrl"`
	PrivacyURL  *string `json:"privacyUrl"`
	TermsURL    *string `json:"termsUrl"`
	// OpenID Connect
	Type                   *string   `json:"type"`
	RedirectURIs           *[]string `json:"redirectUris"`
	PostLogoutRedirectURIs *[]string `json:"postLogoutRedirectUris"`
	Scopes                 *[]string `json:"scopes"`
	// SAML: metadata from a URL, pasted XML, or an entity ID and ACS URL.
	MetadataURL *string `json:"metadataUrl"`
	MetadataXML *string `json:"metadataXml"`
	EntityID    *string `json:"entityId"`
	ACSURL      *string `json:"acsUrl"`
}

func (a *API) createOwnApp(w http.ResponseWriter, r *http.Request) {
	var body ownAppBody
	if !decode(w, r, &body) {
		return
	}
	protocol := deref(body.Protocol)
	if protocol != "oidc" && protocol != "saml" {
		writeFieldError(w, "protocol", "Choose OpenID Connect or SAML")
		return
	}
	c := &store.Client{ID: store.NewClientID(), Protocol: protocol, PostLogoutRedirectURIs: []string{},
		RequiredScopes: []string{"openid"}, RedirectURIs: []string{}}
	if protocol == "oidc" {
		switch deref(body.Type) {
		case typeWeb:
		case typeNative:
			c.Native = true
		default:
			writeFieldError(w, "type", "Choose the type of app")
			return
		}
		if body.RedirectURIs == nil {
			body.RedirectURIs = &[]string{}
		}
	} else if body.MetadataURL == nil && body.MetadataXML == nil && body.EntityID == nil {
		body.EntityID = new(string) // asks for the entity ID
	}
	if body.Name == nil {
		body.Name = new(string)
	}
	a.saveOwnApp(w, r, c, &body, http.StatusCreated)
}

func (a *API) updateOwnApp(w http.ResponseWriter, r *http.Request) {
	c := a.ownApp(w, r)
	if c == nil {
		return
	}
	var body ownAppBody
	if !decode(w, r, &body) {
		return
	}
	a.saveOwnApp(w, r, c, &body, http.StatusOK)
}

// saveOwnApp applies the fields that were sent, checks them and saves.
func (a *API) saveOwnApp(w http.ResponseWriter, r *http.Request, c *store.Client, body *ownAppBody, status int) {
	ctx := r.Context()
	org := organisation(r)
	c.Publisher = org.Name

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

	if c.Protocol == "saml" {
		a.saveSAMLApp(w, r, c, body, status)
		return
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
				writeFieldError(w, "scopes", "Choose from profile, email and offline_access")
				return
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		c.RequiredScopes = scopes
	}

	newApp := status == http.StatusCreated
	if err := a.store.SaveOrganisationClient(ctx, a.store.DB, org.ID, c); err != nil {
		serverError(w, r, err)
		return
	}
	var newSecret string
	if newApp && !c.Native {
		var err error
		if newSecret, err = a.store.SetClientSecret(ctx, org.ID, c.ID); err != nil {
			serverError(w, r, err)
			return
		}
	}
	slog.Info("own app saved", "app", c.ID, "protocol", "oidc", "organisation", org.ID, "by", caller(r).ID)
	saved, err := a.store.OrganisationClient(ctx, org.ID, c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditOwnApp(r, status, saved)
	a.writeOwnApp(w, r, status, saved, newSecret)
}

func (a *API) saveSAMLApp(w http.ResponseWriter, r *http.Request, c *store.Client, body *ownAppBody, status int) {
	ctx := r.Context()
	org := organisation(r)
	app := &store.SAMLApp{ClientID: c.ID}
	if status != http.StatusCreated {
		existing, err := a.store.SAMLApp(ctx, c.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		app = existing
	}

	switch {
	case body.MetadataURL != nil && strings.TrimSpace(*body.MetadataURL) != "":
		raw := strings.TrimSpace(*body.MetadataURL)
		data, err := samlidp.FetchSPMetadata(ctx, raw)
		if err != nil {
			writeFieldError(w, "metadataUrl", err.Error())
			return
		}
		ed, acs, err := samlidp.ParseSPMetadata(data)
		if err != nil {
			writeFieldError(w, "metadataUrl", err.Error())
			return
		}
		app.MetadataURL, app.Metadata, app.EntityID, app.ACSURL = raw, string(data), ed.EntityID, acs
	case body.MetadataXML != nil && strings.TrimSpace(*body.MetadataXML) != "":
		data := []byte(strings.TrimSpace(*body.MetadataXML))
		ed, acs, err := samlidp.ParseSPMetadata(data)
		if err != nil {
			writeFieldError(w, "metadataXml", err.Error())
			return
		}
		app.MetadataURL, app.Metadata, app.EntityID, app.ACSURL = "", string(data), ed.EntityID, acs
	case body.EntityID != nil || body.ACSURL != nil:
		entityID, acs := app.EntityID, app.ACSURL
		if body.EntityID != nil {
			entityID = strings.TrimSpace(*body.EntityID)
		}
		if body.ACSURL != nil {
			acs = strings.TrimSpace(*body.ACSURL)
		}
		if entityID == "" || len(entityID) > 1024 {
			writeFieldError(w, "entityId", "Enter the app's entity ID (from its SAML settings)")
			return
		}
		if !httpsURL(acs) && !loopback(acs) {
			writeFieldError(w, "acsUrl", "Enter the app's https:// ACS URL (from its SAML settings)")
			return
		}
		md, err := samlidp.MakeSPMetadata(entityID, acs)
		if err != nil {
			serverError(w, r, err)
			return
		}
		app.MetadataURL, app.Metadata, app.EntityID, app.ACSURL = "", md, entityID, acs
	}
	if !httpsURL(app.ACSURL) && !loopback(app.ACSURL) {
		writeFieldError(w, "acsUrl", "The app's ACS URL must be https://")
		return
	}
	if other, err := a.store.SAMLAppByEntityID(ctx, org.ID, app.EntityID); err == nil && other.ClientID != c.ID {
		writeFieldError(w, "entityId", "Another of your apps already uses this entity ID")
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		serverError(w, r, err)
		return
	}
	if err := a.store.SaveSAMLApp(ctx, org.ID, c, app); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("own app saved", "app", c.ID, "protocol", "saml", "organisation", org.ID, "by", caller(r).ID)
	saved, err := a.store.OrganisationClient(ctx, org.ID, c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditOwnApp(r, status, saved)
	a.writeOwnApp(w, r, status, saved, "")
}

func (a *API) deleteOwnApp(w http.ResponseWriter, r *http.Request) {
	c := a.ownApp(w, r)
	if c == nil {
		return
	}
	if err := a.store.DeleteOrganisationClient(r.Context(), organisation(r).ID, c.ID); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("own app deleted", "app", c.ID, "organisation", organisation(r).ID, "by", caller(r).ID)
	a.audit(r, store.ActionOwnAppDeleted, aboutApp(c), "")
	w.WriteHeader(http.StatusNoContent)
}

// newOwnAppSecret: "Generate a new secret". Web apps only.
func (a *API) newOwnAppSecret(w http.ResponseWriter, r *http.Request) {
	c := a.ownApp(w, r)
	if c == nil {
		return
	}
	if c.Protocol != "oidc" || c.Native {
		writeError(w, http.StatusConflict, "no_secret", "Only web apps have a secret.")
		return
	}
	value, err := a.store.SetClientSecret(r.Context(), organisation(r).ID, c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("own app secret changed", "app", c.ID, "by", caller(r).ID)
	a.audit(r, store.ActionOwnAppSecret, aboutApp(c), "The old secret stopped working")
	c, _ = a.store.OrganisationClient(r.Context(), organisation(r).ID, c.ID)
	a.writeOwnApp(w, r, http.StatusOK, c, value)
}

// ── Checking links ───────────────────────────────────────────────────────

func httpsURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Fragment == ""
}

func loopback(v string) bool {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "http" || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// customScheme: an app's own scheme, e.g. com.example.app:/callback.
func customScheme(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" &&
		u.Scheme != "javascript" && u.Scheme != "data" && u.Scheme != "file" && u.Fragment == "" &&
		strings.Contains(u.Scheme, ".")
}

// cleanRedirects trims and de-duplicates; bad is the first one not allowed.
// Web apps: https (or http://localhost while developing). Single-page and
// mobile apps: also their own scheme (reverse domain, e.g. com.example.app).
func cleanRedirects(in []string, native bool) (out []string, bad string) {
	out = []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !httpsURL(v) && !loopback(v) && !(native && customScheme(v)) {
			return nil, v
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) > 20 {
		return nil, out[20]
	}
	return out, ""
}

func redirectHelp(bad string, native bool) string {
	msg := "Enter https:// addresses"
	if native {
		msg = "Enter https:// addresses, or your app's own scheme (e.g. com.example.app:/callback)"
	}
	if bad != "" {
		return bad + " can't be used. " + msg
	}
	return "Enter at least one redirect URI. " + msg
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (a *API) auditOwnApp(r *http.Request, status int, c *store.Client) {
	kind := map[string]string{"oidc": "OpenID Connect", "saml": "SAML"}[c.Protocol]
	if status == http.StatusCreated {
		a.audit(r, store.ActionOwnAppCreated, aboutApp(c), kind)
	} else {
		a.audit(r, store.ActionOwnAppUpdated, aboutApp(c), kind)
	}
}
