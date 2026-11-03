package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Groups
func handleAPIGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, 405, "method not allowed")
		return
	}
	groups, err := getGroupsList()
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, groups)
}

func handleAPIGroupRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, 405, "method not allowed")
		return
	}
	var req struct{ OldName, NewName string }
	json.NewDecoder(r.Body).Decode(&req)
	if req.OldName == "" || req.NewName == "" {
		apiError(w, 400, "old_name and new_name required")
		return
	}
	renameGroupInUsers(req.OldName, req.NewName)
	writeJSON(w, 200, map[string]string{"status": "renamed"})
}

func handleAPIGroupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, 405, "method not allowed")
		return
	}
	var req struct{ Name string }
	json.NewDecoder(r.Body).Decode(&req)
	if req.Name == "" {
		apiError(w, 400, "name required")
		return
	}
	deleteGroupInUsers(req.Name)
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// OIDC Clients
func handleAPIClients(w http.ResponseWriter, r *http.Request) {
	clients, _ := readOIDCClients()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, clients)
	case http.MethodPost:
		var c OIDCClient
		json.NewDecoder(r.Body).Decode(&c)
		if c.ID == "" {
			apiError(w, 400, "client id required")
			return
		}
		rawSecret := ""
		if !c.Public && c.Secret == "" {
			rawSecret, _ = generateRandomSecret(24)
			h, _ := hashArgon2id(rawSecret)
			c.Secret = h
		} else if !c.Public && c.Secret != "" && !strings.HasPrefix(c.Secret, "$argon2") {
			rawSecret = c.Secret
			h, _ := hashArgon2id(c.Secret)
			c.Secret = h
		}
		clients = append(clients, c)
		writeOIDCClients(clients)
		writeJSON(w, 201, map[string]interface{}{"status": "created", "client_id": c.ID, "raw_secret": rawSecret})
	default:
		apiError(w, 405, "method not allowed")
	}
}

func handleAPIClientItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	id, _ = url.PathUnescape(id)
	clients, _ := readOIDCClients()
	idx := -1
	for i, c := range clients {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		apiError(w, 404, "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, clients[idx])
	case http.MethodPut:
		var c OIDCClient
		json.NewDecoder(r.Body).Decode(&c)
		c.ID = id
		if c.Secret == "" {
			c.Secret = clients[idx].Secret
		} else if !strings.HasPrefix(c.Secret, "$argon2") {
			h, _ := hashArgon2id(c.Secret)
			c.Secret = h
		}
		clients[idx] = c
		writeOIDCClients(clients)
		writeJSON(w, 200, map[string]string{"status": "updated"})
	case http.MethodDelete:
		clients = append(clients[:idx], clients[idx+1:]...)
		writeOIDCClients(clients)
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	default:
		apiError(w, 405, "method not allowed")
	}
}
