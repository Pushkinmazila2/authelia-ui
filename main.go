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
	if len(os.Args) > 1 && os.Args[1] == "guard" {
		mode = "guard"
	}

	if mode == "guard" {
		runGuard()
	} else {
		runUI()
	}
}

func runUI() {
	log.Printf("[ui] Authelia UI starting on %s...", listenAddr)
	log.Printf("[ui] Config: %s | Users: %s | DB: %s", configPath, usersPath, dbPath)
	if guardURL != "" {
		log.Printf("[ui] Guard proxy configured: %s", guardURL)
	}

	http.HandleFunc("/", handleUIRoute)
	http.HandleFunc("/restart", handleUIRestart)
	http.HandleFunc("/users/save", handleUIUserSave)
	http.HandleFunc("/users/delete", handleUIUserDelete)
	http.HandleFunc("/rules/save", handleUIRuleSave)
	http.HandleFunc("/rules/move", handleUIRuleMove)
	http.HandleFunc("/rules/delete", handleUIRuleDelete)
	http.HandleFunc("/sessions/delete", handleUISessionDelete)

	server := &http.Server{
		Addr:         listenAddr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

