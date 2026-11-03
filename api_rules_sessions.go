package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Rules
func handleAPIRules(w http.ResponseWriter, r *http.Request) {
	rawCfg, ac, _ := readConfigFile()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, ac)
	case http.MethodPost:
		var rule AccessControlRule
		json.NewDecoder(r.Body).Decode(&rule)
		ac.Rules = append(ac.Rules, rule)
		writeConfigFile(rawCfg, ac)
		writeJSON(w, 201, map[string]string{"status": "created"})
	default:
		apiError(w, 405, "method not allowed")
	}
}

func handleAPIRuleItem(w http.ResponseWriter, r *http.Request) {
	idxStr := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	idx, _ := strconv.Atoi(idxStr)
	rawCfg, ac, _ := readConfigFile()
	if idx < 0 || idx >= len(ac.Rules) {
		apiError(w, 404, "index out of range")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, ac.Rules[idx])
	case http.MethodPut:
		var rule AccessControlRule
		json.NewDecoder(r.Body).Decode(&rule)
		ac.Rules[idx] = rule
		writeConfigFile(rawCfg, ac)
		writeJSON(w, 200, map[string]string{"status": "updated"})
	case http.MethodDelete:
		ac.Rules = append(ac.Rules[:idx], ac.Rules[idx+1:]...)
		writeConfigFile(rawCfg, ac)
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	default:
		apiError(w, 405, "method not allowed")
	}
}

// Sessions & Logs
func handleAPISessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, 405, "method not allowed")
		return
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	defer db.Close()
	type SRow struct{ Key, Exp string }
	var list []SRow
	for _, tbl := range []string{"session", "sessions", "authentication_sessions"} {
		rows, err := db.Query("SELECT key, expiry FROM " + tbl + " LIMIT 200")
		if err == nil {
			for rows.Next() {
				var k string
				var exp int64
				rows.Scan(&k, &exp)
				list = append(list, SRow{k, time.Unix(exp, 0).UTC().Format(time.RFC3339)})
			}
			rows.Close()
			break
		}
	}
	if list == nil {
		list = []SRow{}
	}
	writeJSON(w, 200, list)
}

func handleAPISessionItem(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	db, _ := sql.Open("sqlite", "file:"+dbPath+"?_journal=WAL")
	defer db.Close()
	for _, tbl := range []string{"session", "sessions", "authentication_sessions"} {
		db.Exec("DELETE FROM "+tbl+" WHERE key = ?", key)
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	if guardURL != "" {
		c := &http.Client{Timeout: 5 * time.Second}
		resp, err := c.Get(guardURL + "/api/guard/logs?tail=200")
		if err != nil {
			apiError(w, 502, err.Error())
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.Copy(w, resp.Body)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("GUARD_URL not configured"))
}
