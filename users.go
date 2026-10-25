package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"

	"golang.org/x/crypto/bcrypt"
)

// memoryUser is the dev fallback user record (plaintext password; dev only).
type memoryUser struct {
	Password string
	Name     string
	Email    string
	Status   string
}

var memoryUsers = map[string]memoryUser{
	"admin":            {Password: "password", Name: "Administrator", Email: "admin@keston.local", Status: "active"},
	"john@oakside.com": {Password: "password", Name: "John", Email: "john@oakside.com", Status: "active"},
}

func listUsers(ctx context.Context) ([]User, error) {
	if sqlStore != nil {
		return sqlStore.ListUsers(ctx)
	}
	mu.Lock()
	defer mu.Unlock()
	out := make([]User, 0, len(memoryUsers))
	for username, u := range memoryUsers {
		out = append(out, User{Username: username, Name: u.Name, Email: u.Email, Status: u.Status})
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
	if _, exists := memoryUsers[username]; exists {
		return errors.New("user already exists")
	}
	memoryUsers[username] = memoryUser{Password: password, Name: name, Email: email, Status: "active"}
	return nil
}

func updateUser(ctx context.Context, username, name, email string) error {
	if sqlStore != nil {
		return sqlStore.UpdateUser(ctx, username, name, email)
	}
	mu.Lock()
	defer mu.Unlock()
	u, ok := memoryUsers[username]
	if !ok {
		return errors.New("user not found")
	}
	u.Name = name
	u.Email = email
	memoryUsers[username] = u
	return nil
}

func deleteUser(ctx context.Context, username string) error {
	if sqlStore != nil {
		return sqlStore.DeleteUser(ctx, username)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := memoryUsers[username]; !ok {
		return errors.New("user not found")
	}
	delete(memoryUsers, username)
	return nil
}

func setUserPassword(ctx context.Context, username, password string) error {
	if sqlStore != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		return sqlStore.SetUserPassword(ctx, username, string(hash))
	}
	mu.Lock()
	defer mu.Unlock()
	u, ok := memoryUsers[username]
	if !ok {
		return errors.New("user not found")
	}
	u.Password = password
	memoryUsers[username] = u
	return nil
}

func setUserStatus(ctx context.Context, username, status string) error {
	if sqlStore != nil {
		return sqlStore.SetUserStatus(ctx, username, status)
	}
	mu.Lock()
	defer mu.Unlock()
	u, ok := memoryUsers[username]
	if !ok {
		return errors.New("user not found")
	}
	u.Status = status
	memoryUsers[username] = u
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

// formValues reads form values from the request body (any method) or, failing
// that, the URL query string.
func formValues(r *http.Request) url.Values {
	if r.Body != nil {
		if b, err := io.ReadAll(r.Body); err == nil {
			if vals, err := url.ParseQuery(string(b)); err == nil {
				return vals
			}
		}
	}
	return r.URL.Query()
}

// usersHandler manages Keston ID users. Requires client auth.
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
		vals := formValues(r)
		username := vals.Get("username")
		password := vals.Get("password")
		name := vals.Get("name")
		email := vals.Get("email")
		if email == "" {
			email = username
		}
		if username == "" || password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "username and password required"})
			return
		}
		if err := createUser(r.Context(), username, password, name, email); err != nil {
			writeJSON(w, http.StatusConflict, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{"ok": true})

	case http.MethodPut:
		vals := formValues(r)
		username := vals.Get("username")
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "username required"})
			return
		}
		name := vals.Get("name")
		email := vals.Get("email")
		password := vals.Get("password")
		status := vals.Get("status")

		if password != "" {
			if err := setUserPassword(r.Context(), username, password); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
				return
			}
		}
		if status != "" {
			if err := setUserStatus(r.Context(), username, status); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
				return
			}
		}
		if name != "" || email != "" {
			if err := updateUser(r.Context(), username, name, email); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})

	case http.MethodDelete:
		vals := formValues(r)
		username := vals.Get("username")
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "username required"})
			return
		}
		if err := deleteUser(r.Context(), username); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
