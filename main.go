package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	mode := strings.ToLower(os.Getenv("MODE"))
	if len(os.Args) > 1 {
		arg := strings.ToLower(os.Args[1])
		if arg == "guard" || arg == "api" || arg == "ui" {
			mode = arg
		}
	}

	switch mode {
	case "guard":
		runGuard()
	case "api":
		runAPI()
	default:
		runUI()
	}
}

func runAPI() {
	log.Printf("[api] Authelia Headless API starting on %s...", listenAddr)
	log.Printf("[api] Config: %s | Users: %s | DB: %s", configPath, usersPath, dbPath)
	if guardURL != "" {
		log.Printf("[api] Guard proxy configured: %s", guardURL)
	}

	mux := http.NewServeMux()
	registerAPIEndpoints(mux)

	// Fallback for non-API routes in headless mode
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"headless api mode active. UI is disabled. Use /api endpoints with Bearer token."}`))
			return
		}
	})

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func runUI() {
	log.Printf("[ui] Authelia UI starting on %s...", listenAddr)
	log.Printf("[ui] Config: %s | Users: %s | DB: %s", configPath, usersPath, dbPath)
	if guardURL != "" {
		log.Printf("[ui] Guard proxy configured: %s", guardURL)
	}

	mux := http.NewServeMux()

	// Public Auth endpoints
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)

	// Protected UI endpoints
	mux.HandleFunc("/", uiAuthMiddleware(handleUIRoute))
	mux.HandleFunc("/restart", uiAuthMiddleware(handleUIRestart))
	mux.HandleFunc("/users/save", uiAuthMiddleware(handleUIUserSave))
	mux.HandleFunc("/users/delete", uiAuthMiddleware(handleUIUserDelete))
	mux.HandleFunc("/groups/add", uiAuthMiddleware(handleUIGroupAdd))
	mux.HandleFunc("/groups/rename", uiAuthMiddleware(handleUIGroupRename))
	mux.HandleFunc("/groups/delete", uiAuthMiddleware(handleUIGroupDelete))
	mux.HandleFunc("/clients/save", uiAuthMiddleware(handleUIClientSave))
	mux.HandleFunc("/clients/delete", uiAuthMiddleware(handleUIClientDelete))
	mux.HandleFunc("/clients/jwks/generate", uiAuthMiddleware(handleUIJWKSGenerate))
	mux.HandleFunc("/rules/save", uiAuthMiddleware(handleUIRuleSave))
	mux.HandleFunc("/rules/move", uiAuthMiddleware(handleUIRuleMove))
	mux.HandleFunc("/rules/delete", uiAuthMiddleware(handleUIRuleDelete))
	mux.HandleFunc("/sessions/delete", uiAuthMiddleware(handleUISessionDelete))

	// Embedded REST API endpoints (bearer-token protected)
	registerAPIEndpoints(mux)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}


