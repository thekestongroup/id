package main

import (
	"context"
	"net/http"
	"sort"

	"golang.org/x/crypto/bcrypt"
)

// memoryUser is the dev fallback user record (plaintext password; dev only).
type memoryUser struct {
	Password string
	Name     string
	Email    string
}

var memoryUsers = map[string]memoryUser{
	"admin":            {Password: "password", Name: "Administrator", Email: "admin@keston.local"},
	"john@oakside.com": {Password: "password", Name: "John", Email: "john@oakside.com"},
}

func listUsers(ctx context.Context) ([]User, error) {
	if sqlStore != nil {
		return sqlStore.ListUsers(ctx)
	}
	mu.Lock()
	defer mu.Unlock()
	out := make([]User, 0, len(memoryUsers))
	for username, u := range memoryUsers {
		out = append(out, User{Username: username, Name: u.Name, Email: u.Email})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func createUser(ctx context.Context, username, password, name, email string) error {
	if sqlStore != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		return sqlStore.CreateUser(ctx, username, string(hash), name, email)
	}
	mu.Lock()
	defer mu.Unlock()
	memoryUsers[username] = memoryUser{Password: password, Name: name, Email: email}
	return nil
}

func getUserInfo(ctx context.Context, username string) (string, string) {
	if sqlStore != nil {
		if name, email, err := sqlStore.GetUserInfo(ctx, username); err == nil {
			return name, email
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if u, ok := memoryUsers[username]; ok {
		return u.Name, u.Email
	}
	return "", username
}

// usersHandler lists and creates Keston ID users. Requires client auth.
func usersHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := authenticateClient(r.Context(), r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		users, err := listUsers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"users": users})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		name := r.PostFormValue("name")
		email := r.PostFormValue("email")
		if email == "" {
			email = username
		}
		if username == "" || password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "username and password required"})
			return
		}
		if err := createUser(r.Context(), username, password, name, email); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
