package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func registerAPIEndpoints(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", apiAuthMiddleware(handleAPIStatus))
	mux.HandleFunc("/api/restart", apiAuthMiddleware(handleAPIRestart))

	mux.HandleFunc("/api/users", apiAuthMiddleware(handleAPIUsers))
	mux.HandleFunc("/api/users/", apiAuthMiddleware(handleAPIUserItem))

	mux.HandleFunc("/api/groups", apiAuthMiddleware(handleAPIGroups))
	mux.HandleFunc("/api/groups/rename", apiAuthMiddleware(handleAPIGroupRename))
	mux.HandleFunc("/api/groups/delete", apiAuthMiddleware(handleAPIGroupDelete))

	mux.HandleFunc("/api/clients", apiAuthMiddleware(handleAPIClients))
	mux.HandleFunc("/api/clients/", apiAuthMiddleware(handleAPIClientItem))

	mux.HandleFunc("/api/rules", apiAuthMiddleware(handleAPIRules))
	mux.HandleFunc("/api/rules/", apiAuthMiddleware(handleAPIRuleItem))

	mux.HandleFunc("/api/sessions", apiAuthMiddleware(handleAPISessions))
	mux.HandleFunc("/api/sessions/", apiAuthMiddleware(handleAPISessionItem))

	mux.HandleFunc("/api/logs", apiAuthMiddleware(handleAPILogs))
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, queryStatus())
}

func handleAPIRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if guardURL != "" {
		c := &http.Client{}
		resp, err := c.Post(guardURL+"/api/guard/restart", "application/json", nil)
		if err != nil {
			apiError(w, http.StatusBadGateway, err.Error())
			return
		}
		defer resp.Body.Close()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarted"})
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	udb, err := readUsersFile()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch r.Method {
	case http.MethodGet:
		type UDTO struct {
			Username    string   `json:"username"`
			DisplayName string   `json:"displayname"`
			Email       string   `json:"email"`
			Groups      []string `json:"groups"`
			Disabled    bool     `json:"disabled"`
		}
		list := make([]UDTO, 0, len(udb.Users))
		for u, rec := range udb.Users {
			g := rec.Groups
			if g == nil {
				g = []string{}
			}
			list = append(list, UDTO{u, rec.DisplayName, rec.Email, g, rec.Disabled})
		}
		writeJSON(w, http.StatusOK, list)

	case http.MethodPost:
		var req struct {
			Username    string   `json:"username"`
			DisplayName string   `json:"displayname"`
			Email       string   `json:"email"`
			Groups      []string `json:"groups"`
			Password    string   `json:"password"`
			Disabled    bool     `json:"disabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Username == "" || req.Password == "" {
			apiError(w, http.StatusBadRequest, "username and password required")
			return
		}
		if _, exists := udb.Users[req.Username]; exists {
			apiError(w, http.StatusConflict, "user already exists")
			return
		}
		h, err := hashArgon2id(req.Password)
		if err != nil {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		g := req.Groups
		if g == nil {
			g = []string{}
		}
		udb.Users[req.Username] = UserRecord{
			Password:    h,
			DisplayName: req.DisplayName,
			Email:       req.Email,
			Groups:      g,
			Disabled:    req.Disabled,
		}
		writeUsersFile(udb)
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "username": req.Username})
	default:
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleAPIUserItem(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/users/")
	username, _ = url.PathUnescape(username)
	udb, _ := readUsersFile()
	rec, exists := udb.Users[username]
	if !exists {
		apiError(w, http.StatusNotFound, "user not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"username":    username,
			"displayname": rec.DisplayName,
			"email":       rec.Email,
			"groups":      rec.Groups,
			"disabled":    rec.Disabled,
		})
	case http.MethodPut:
		var req struct {
			DisplayName string   `json:"displayname"`
			Email       string   `json:"email"`
			Groups      []string `json:"groups"`
			Password    string   `json:"password"`
			Disabled    *bool    `json:"disabled"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.DisplayName != "" {
			rec.DisplayName = req.DisplayName
		}
		if req.Email != "" {
			rec.Email = req.Email
		}
		if req.Groups != nil {
			rec.Groups = req.Groups
		}
		if req.Disabled != nil {
			rec.Disabled = *req.Disabled
		}
		if req.Password != "" {
			h, _ := hashArgon2id(req.Password)
			rec.Password = h
		}
		udb.Users[username] = rec
		writeUsersFile(udb)
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	case http.MethodDelete:
		delete(udb.Users, username)
		writeUsersFile(udb)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
