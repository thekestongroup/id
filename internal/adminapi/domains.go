package adminapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// An organisation's domains. Its people's emails are username@one of its
// verified domains; one is primary (the default for new people). A domain
// is verified by a DNS TXT record:
//
//	_keston-verification.<domain>   TXT   keston-verify=<token>
//
// (the same value at the domain's own apex works too, for DNS hosts that
// make subdomains awkward), or by a TKG Admin without DNS: an override,
// kept and shown as such.

// TXTResolver is the DNS lookup domain verification needs (a *net.Resolver;
// tests replace it).
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

const dnsTimeout = 5 * time.Second

type domainJSON struct {
	store.OrgDomain
	// For an unverified domain: the TXT record to create.
	Record *txtRecord `json:"record,omitempty"`
}

type txtRecord struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func domainView(d store.OrgDomain) domainJSON {
	v := domainJSON{OrgDomain: d}
	if !d.Verified {
		name, value := d.VerificationRecord()
		v.Record = &txtRecord{name, value}
	}
	return v
}

// domainNames: the organisation's verified domains, the primary first.
func (a *API) domainNames(r *http.Request, org *store.Organisation) []string {
	names, err := a.store.VerifiedDomains(r.Context(), org.ID)
	if err != nil || len(names) == 0 {
		return []string{org.Domain}
	}
	return names
}

// userDomain: the domain for someone's email: the one asked for, else
// `fallback` (their current one, when changing a username), else the
// primary. It must be one of the organisation's verified domains.
func (a *API) userDomain(w http.ResponseWriter, r *http.Request, org *store.Organisation, asked, fallback string) (string, bool) {
	domain := strings.ToLower(strings.TrimSpace(asked))
	if domain == "" {
		if fallback != "" {
			return strings.ToLower(fallback), true
		}
		return strings.ToLower(org.Domain), true
	}
	names, err := a.store.VerifiedDomains(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return "", false
	}
	for _, n := range names {
		if n == domain {
			return domain, true
		}
	}
	writeFieldError(w, "domain", domain+" isn't one of this organisation's verified domains.")
	return "", false
}

// domainAccess: managing domains needs Settings here, or being a TKG Admin
// (who can see and help any organisation's domains, without support access).
func (a *API) domainAccess(w http.ResponseWriter, r *http.Request) bool {
	if can(r, store.PermSettings) || caller(r).PlatformAdmin {
		return true
	}
	if caller(r).OrganisationID != organisation(r).ID {
		writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can manage another organisation's domains.")
		return false
	}
	writeError(w, http.StatusForbidden, "no_permission", "You don't have permission to do that. Ask one of your global admins.")
	return false
}

// GET …/domains
func (a *API) listDomains(w http.ResponseWriter, r *http.Request) {
	if !a.domainAccess(w, r) {
		return
	}
	list, err := a.store.OrganisationDomains(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := make([]domainJSON, len(list))
	for i, d := range list {
		out[i] = domainView(d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out, "canOverride": caller(r).PlatformAdmin})
}

// POST …/domains {domain, override?}: add a domain, unverified (create the
// TXT record, then verify) or, for TKG Admins with override, verified now.
func (a *API) addDomain(w http.ResponseWriter, r *http.Request) {
	if !a.domainAccess(w, r) {
		return
	}
	u, org := caller(r), organisation(r)
	var body struct {
		Domain   string `json:"domain"`
		Override bool   `json:"override"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Override && !u.PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can add a domain without checking DNS.")
		return
	}
	domain := normaliseDomain(body.Domain)
	if !validDomain(domain) {
		writeFieldError(w, "domain", domainHelp)
		return
	}
	d, err := a.store.AddDomain(r.Context(), org.ID, domain, u, body.Override)
	if errors.Is(err, store.ErrDomainTaken) {
		writeFieldError(w, "domain", domain+" already belongs to an organisation.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	if body.Override {
		a.audit(r, store.ActionDomainAdded, aboutOrg(org), "Domain: "+domain+" (added as verified by a TKG Admin without DNS: override)")
	} else {
		a.audit(r, store.ActionDomainAdded, aboutOrg(org), "Domain: "+domain+" (waiting for verification)")
	}
	writeJSON(w, http.StatusCreated, domainView(*d))
}

// POST …/domains/{domainID}/verify: look the TXT record up. Verifying a
// verified domain does nothing.
func (a *API) verifyDomain(w http.ResponseWriter, r *http.Request) {
	if !a.domainAccess(w, r) {
		return
	}
	org := organisation(r)
	d, err := a.store.OrganisationDomain(r.Context(), org.ID, chi.URLParam(r, "domainID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "That domain isn't one of this organisation's.")
		return
	}
	if !d.Verified {
		found, err := a.hasVerificationRecord(r.Context(), d)
		if err != nil {
			writeError(w, http.StatusBadGateway, "dns_unavailable",
				"We couldn't look up the DNS records for "+d.Domain+" just now. Try again in a moment.")
			return
		}
		if !found {
			name, value := d.VerificationRecord()
			writeError(w, http.StatusUnprocessableEntity, "record_not_found",
				"We couldn't find the TXT record "+name+" = "+value+". DNS changes can take a while to spread: try again later.")
			return
		}
		changed, err := a.store.MarkDomainVerified(r.Context(), org.ID, d.ID, caller(r))
		if err != nil {
			serverError(w, r, err)
			return
		}
		if changed {
			a.audit(r, store.ActionDomainVerified, aboutOrg(org), "Domain: "+d.Domain+" (verified by DNS)")
		}
	}
	a.respondDomain(w, r, org.ID, d.ID, http.StatusOK)
}

func (a *API) respondDomain(w http.ResponseWriter, r *http.Request, orgID, id string, status int) {
	d, err := a.store.OrganisationDomain(r.Context(), orgID, id)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, status, domainView(*d))
}

// hasVerificationRecord: one of the domain's TXT records (at
// _keston-verification.<domain> or the domain itself) is the token.
func (a *API) hasVerificationRecord(ctx context.Context, d *store.OrgDomain) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	name, want := d.VerificationRecord()
	var lastErr error
	failed := 0
	for _, host := range []string{name, d.Domain} {
		records, err := a.resolver.LookupTXT(ctx, host)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			failed++ // nothing there: not an error
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}
		for _, rec := range records {
			if strings.TrimSpace(rec) == want {
				return true, nil
			}
		}
	}
	if lastErr != nil && failed == 0 {
		return false, lastErr
	}
	return false, nil
}

// POST …/domains/{domainID}/primary {renameUsers?}: make it the primary
// domain. Existing people keep their emails unless renameUsers.
func (a *API) makePrimaryDomain(w http.ResponseWriter, r *http.Request) {
	if !a.domainAccess(w, r) {
		return
	}
	org := organisation(r)
	d, err := a.store.OrganisationDomain(r.Context(), org.ID, chi.URLParam(r, "domainID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "That domain isn't one of this organisation's.")
		return
	}
	var body struct {
		RenameUsers bool `json:"renameUsers"`
	}
	if err := decodeOptional(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the request.")
		return
	}
	before := org.Domain
	renamed, err := a.store.SetPrimaryDomain(r.Context(), org.ID, d.ID, body.RenameUsers)
	switch {
	case errors.Is(err, store.ErrDomainUnverif):
		writeError(w, http.StatusConflict, "unverified", "Verify "+d.Domain+" before making it the primary domain.")
		return
	case errors.Is(err, store.ErrRenameConflicts):
		writeError(w, http.StatusConflict, "rename_conflict",
			"Some people already have the same username at "+d.Domain+", so we can't rename everyone. Nothing was changed.")
		return
	case err != nil:
		serverError(w, r, err)
		return
	}
	sum := change("Primary domain", before, d.Domain)
	if body.RenameUsers {
		sum += "; renamed " + strconv.Itoa(renamed) + " users to " + d.Domain
	}
	if sum != "" {
		a.audit(r, store.ActionDomainPrimary, aboutOrg(org), sum)
	}
	a.respondDomain(w, r, org.ID, d.ID, http.StatusOK)
}

// DELETE …/domains/{domainID}: not the primary one, nor one people use.
func (a *API) removeDomain(w http.ResponseWriter, r *http.Request) {
	if !a.domainAccess(w, r) {
		return
	}
	org := organisation(r)
	d, err := a.store.OrganisationDomain(r.Context(), org.ID, chi.URLParam(r, "domainID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "That domain isn't one of this organisation's.")
		return
	}
	switch err := a.store.RemoveDomain(r.Context(), org.ID, d.ID); {
	case errors.Is(err, store.ErrDomainPrimary):
		writeError(w, http.StatusConflict, "primary", "Make another domain primary before removing "+d.Domain+".")
		return
	case errors.Is(err, store.ErrDomainInUse):
		writeError(w, http.StatusConflict, "in_use", "People still have "+d.Domain+" emails. Move or rename them first.")
		return
	case err != nil:
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionDomainRemoved, aboutOrg(org), "Domain: "+d.Domain)
	w.WriteHeader(http.StatusNoContent)
}
