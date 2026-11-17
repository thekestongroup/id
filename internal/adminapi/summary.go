package adminapi

import (
	"net/http"

	"github.com/thekestongroup/id/internal/store"
)

// GET …/summary: the counts behind the organisation's dashboard in Keston
// Admin, in one request: users, MFA, groups, apps, licences and the last 7
// days of sign-ins. Counts only. Whoever can see the organisation can see
// them (Keston staff in any organisation, its own people with any
// permission), and no one gets more about its people than a number.
//
// recentActivity (its latest admin actions) is the audit log, so it's only
// there for people with "View reports" in this organisation; otherwise null.
func (a *API) getSummary(w http.ResponseWriter, r *http.Request) {
	org := organisation(r)
	s, err := a.store.OrganisationSummary(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	var recent []store.AuditRecord
	if can(r, store.PermReports) {
		if recent, _, err = a.store.AuditLog(r.Context(), store.LogFilter{OrganisationID: org.ID, Limit: 5}); err != nil {
			serverError(w, r, err)
			return
		}
		if recent == nil {
			recent = []store.AuditRecord{}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		*store.OrgSummary
		RecentActivity []store.AuditRecord `json:"recentActivity"`
	}{s, recent})
}
