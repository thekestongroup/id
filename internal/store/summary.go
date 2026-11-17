package store

import (
	"context"
)

// ── Organisation summary: the counts behind Keston Admin's dashboard ─────

// SummaryDay is one day's sign-ins (UTC), oldest first in OrgSummary.
type SummaryDay struct {
	Date    string `json:"date"` // 2006-01-02
	Success int    `json:"success"`
	Failed  int    `json:"failed"`
}

// OrgSummary: counts only, never people. Users are the organisation's own
// (not Keston support accounts, not deleted ones).
type OrgSummary struct {
	Users struct {
		Total    int `json:"total"`
		Active   int `json:"active"`
		Disabled int `json:"disabled"`
		// Active, but locked out by failed sign-ins until later.
		Locked int `json:"locked"`
		// Told to choose a new password at next sign-in.
		PasswordChangeRequired int `json:"passwordChangeRequired"`
	} `json:"users"`
	MFA struct {
		// off, required or custom (see MFAPolicy).
		Mode string `json:"mode"`
		// Users who can sign in (not disabled), and how many of them have
		// an authenticator app or a passkey.
		Eligible int `json:"eligible"`
		Enrolled int `json:"enrolled"`
	} `json:"mfa"`
	Groups int `json:"groups"`
	Apps   struct {
		// On for everyone by default (forced or enabled), out of all the
		// apps this organisation could use.
		Enabled   int `json:"enabled"`
		Available int `json:"available"`
	} `json:"apps"`
	Licences struct {
		// Licences assigned (one per user per product), and the users who
		// have at least one.
		InUse         int `json:"inUse"`
		LicensedUsers int `json:"licensedUsers"`
		// Unlicensed: people a group gives a licence to who have no seat left
		// (Needs attention), and UnlicensedByProduct the same by product ID.
		Unlicensed          int            `json:"unlicensed"`
		UnlicensedByProduct map[string]int `json:"unlicensedByProduct"`
	} `json:"licences"`
	SignIns struct {
		// The last 7 days (today and the 6 before, UTC).
		Total  int          `json:"total"`
		Failed int          `json:"failed"`
		Daily  []SummaryDay `json:"daily"`
	} `json:"signIns"`
}

// SummaryDays: how many days of sign-ins the summary covers.
const SummaryDays = 7

// OrganisationSummary counts everything in a handful of statements (one for
// users, one for the rest, one for sign-ins), all in SQL.
func (s *Store) OrganisationSummary(ctx context.Context, orgID string) (*OrgSummary, error) {
	var out OrgSummary
	out.SignIns.Daily = []SummaryDay{}
	err := s.DB.QueryRow(ctx, `
		WITH u AS (
			SELECT u.id, u.status, u.password_change_required,
				coalesce(u.status = 'active' AND u.locked_until > now(), false) AS locked,
				(u.totp_enabled OR EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id)) AS mfa
			FROM users u
			WHERE u.organisation_id = $1 AND u.support_for IS NULL AND u.status <> 'deleted')
		SELECT
			count(*),
			count(*) FILTER (WHERE status = 'active' AND NOT locked),
			count(*) FILTER (WHERE status = 'disabled'),
			count(*) FILTER (WHERE locked),
			count(*) FILTER (WHERE password_change_required AND status = 'active'),
			count(*) FILTER (WHERE status = 'active'),
			count(*) FILTER (WHERE status = 'active' AND mfa),
			(SELECT o.mfa_mode FROM organisations o WHERE o.id = $1),
			(SELECT count(*) FROM groups g WHERE g.organisation_id = $1),
			(SELECT count(*) FROM effective_licences l WHERE l.organisation_id = $1 AND l.licensed),
			(SELECT count(DISTINCT l.user_id) FROM effective_licences l WHERE l.organisation_id = $1 AND l.licensed)
		FROM u`, orgID).Scan(&out.Users.Total, &out.Users.Active, &out.Users.Disabled, &out.Users.Locked,
		&out.Users.PasswordChangeRequired, &out.MFA.Eligible, &out.MFA.Enrolled, &out.MFA.Mode, &out.Groups,
		&out.Licences.InUse, &out.Licences.LicensedUsers)
	if err != nil {
		return nil, err
	}
	if out.Licences.Unlicensed, out.Licences.UnlicensedByProduct, err = s.UnlicensedSummary(ctx, orgID); err != nil {
		return nil, err
	}

	// Apps: Keston's own are on by default; anything else only with a
	// default setting. Keston Admin itself is for admins, so it isn't counted.
	err = s.DB.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE coalesce(p.mode, CASE WHEN c.builtin THEN 'forced' END) IN ('forced', 'enabled'))
		FROM clients c
		LEFT JOIN app_policies p ON p.organisation_id = $1 AND p.group_id IS NULL AND p.client_id = c.id
		WHERE c.id <> 'admin' AND (c.organisation_id IS NULL OR c.organisation_id = $1)`, orgID).
		Scan(&out.Apps.Available, &out.Apps.Enabled)
	if err != nil {
		return nil, err
	}

	rows, err := s.DB.Query(ctx, `
		SELECT to_char(d, 'YYYY-MM-DD'),
			count(l.id) FILTER (WHERE l.success), count(l.id) FILTER (WHERE NOT l.success)
		FROM generate_series((now() AT TIME ZONE 'UTC')::date - ($2::int - 1), (now() AT TIME ZONE 'UTC')::date, interval '1 day') AS d
		LEFT JOIN sign_in_log l ON l.organisation_id = $1
			AND (l.created_at AT TIME ZONE 'UTC')::date = d::date
			AND l.created_at >= now() - interval '8 days'
		GROUP BY d ORDER BY d`, orgID, SummaryDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d SummaryDay
		if err := rows.Scan(&d.Date, &d.Success, &d.Failed); err != nil {
			return nil, err
		}
		out.SignIns.Daily = append(out.SignIns.Daily, d)
		out.SignIns.Total += d.Success + d.Failed
		out.SignIns.Failed += d.Failed
	}
	return &out, rows.Err()
}
