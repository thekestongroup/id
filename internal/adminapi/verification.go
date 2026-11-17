package adminapi

import (
	"github.com/thekestongroup/id/internal/clientip"
	"log/slog"
	"net/http"

	"github.com/thekestongroup/id/internal/store"
)

// Organisation verification: while "Require verification for new
// organisations" is on, organisations that sign themselves up
// (public.go) start unverified, and nobody in them can sign in until a
// platform admin verifies them. Organisations made by platform admins, and
// the platform organisation, are always verified.

type platformSettings struct {
	RequireOrganisationVerification bool `json:"requireOrganisationVerification"`
}

// GET /platform-settings: platform admins only.
func (a *API) getPlatformSettings(w http.ResponseWriter, r *http.Request) {
	if !caller(r).PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can see platform settings.")
		return
	}
	on, err := a.store.RequireOrganisationVerification(r.Context())
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, platformSettings{on})
}

// PUT /platform-settings: platform admins only.
func (a *API) putPlatformSettings(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	if !u.PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can change platform settings.")
		return
	}
	var body struct {
		RequireOrganisationVerification *bool `json:"requireOrganisationVerification"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.RequireOrganisationVerification == nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "Say whether to require verification.")
		return
	}
	before, err := a.store.RequireOrganisationVerification(r.Context())
	if err != nil {
		serverError(w, r, err)
		return
	}
	if err := a.store.SetRequireOrganisationVerification(r.Context(), *body.RequireOrganisationVerification); err != nil {
		serverError(w, r, err)
		return
	}
	if before != *body.RequireOrganisationVerification {
		slog.Info("platform setting changed", "setting", "require organisation verification",
			"value", *body.RequireOrganisationVerification, "by", u.ID)
		onOff := map[bool]string{true: "On", false: "Off"}
		a.store.Audit(r.Context(), store.AuditEntry{OrganisationID: u.OrganisationID, Actor: u,
			Action: store.ActionPlatformSettings, TargetType: store.TargetOrganisation, TargetID: u.OrganisationID,
			TargetName: u.Organisation, IP: clientip.From(r),
			Summary: "Require verification for new organisations: " + onOff[before] + " → " +
				onOff[*body.RequireOrganisationVerification]})
	}
	writeJSON(w, http.StatusOK, platformSettings{*body.RequireOrganisationVerification})
}

// POST /organisations/{orgID}/verify: platform admins only.
func (a *API) verifyOrganisation(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org := organisation(r)
	if !u.PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can verify organisations.")
		return
	}
	changed, err := a.store.VerifyOrganisation(r.Context(), org.ID, u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !changed {
		writeError(w, http.StatusConflict, "already_verified", org.Name+" is already verified.")
		return
	}
	slog.Info("organisation verified", "organisation", org.ID, "by", u.ID)
	a.audit(r, store.ActionOrganisationVerified, aboutOrg(org), "Verified")
	updated, err := a.store.OrganisationByID(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
