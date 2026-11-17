package api

// ScopeInfo is how a scope is described to people on the consent prompt and
// the Connected apps page. Icon is a Lucide icon name the web UI maps.
type ScopeInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
}

// "openid" is implied by signing in at all, so it isn't listed on its own.
var scopeCatalog = map[string]ScopeInfo{
	"profile":        {Label: "View your name and profile picture", Description: "To show who's signed in.", Icon: "user"},
	"email":          {Label: "View your email address", Description: "The address you sign in with.", Icon: "mail"},
	"phone":          {Label: "View your phone number", Description: "Your mobile or work number.", Icon: "phone"},
	"keston.profile": {Label: "View your job title, department and manager", Description: "Your work details from your organisation.", Icon: "briefcase"},
	"offline_access": {Label: "Stay connected when you're not using it",
		Description: "So it can sync in the background. You can disconnect it at any time.", Icon: "refresh-cw"},
	"students:read": {Label: "View student records at your school",
		Description: "Names, year groups and contact details. It can't change them.", Icon: "book-open"},
	"staff:read":   {Label: "View staff records at your school", Description: "Names, roles and contact details.", Icon: "users"},
	"courses:read": {Label: "View your courses", Description: "Classes, assignments and grades.", Icon: "graduation-cap"},
	"trips:write":  {Label: "Manage school trips", Description: "Create trips and send consent forms to parents.", Icon: "map-pin"},
}

// describe lists the scopes people should see, in a stable order.
func describe(scopes []string) []ScopeInfo {
	out := make([]ScopeInfo, 0, len(scopes))
	for _, id := range scopes {
		if id == "openid" {
			continue
		}
		info, ok := scopeCatalog[id]
		if !ok {
			info = ScopeInfo{Label: id, Description: "", Icon: "key-round"}
		}
		info.ID = id
		out = append(out, info)
	}
	return out
}
