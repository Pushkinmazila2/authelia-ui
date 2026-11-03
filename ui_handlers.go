package main

import (
	"database/sql"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func handleUIRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/?tab=dashboard", http.StatusSeeOther)
		return
	}
	msg := "Restart triggered."
	if guardURL != "" {
		c := &http.Client{Timeout: 10 * time.Second}
		if resp, err := c.Post(guardURL+"/api/guard/restart", "application/json", nil); err != nil {
			msg = "Error contacting guard: " + err.Error()
		} else {
			resp.Body.Close()
			msg = "Authelia restarted via Docker Guard."
		}
	} else if _, err := os.Stat(dockerSocket); err == nil {
		c := unixDialer()
		if cid, err := findTargetContainer(c); err == nil {
			if resp, err := c.Post("http://localhost/containers/"+cid+"/restart", "application/json", nil); err == nil {
				resp.Body.Close()
				msg = "Authelia restarted via local socket."
			}
		}
	}
	http.Redirect(w, r, "/?tab=dashboard&msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func handleUIUserSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/?tab=users", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	u := strings.TrimSpace(r.FormValue("username"))
	disp := strings.TrimSpace(r.FormValue("displayname"))
	email := strings.TrimSpace(r.FormValue("email"))
	groupsRaw := strings.TrimSpace(r.FormValue("groups"))
	pass := r.FormValue("password")
	disabled := r.FormValue("disabled") == "1"

	if u == "" {
		http.Redirect(w, r, "/?tab=users&msg=Username+required", http.StatusSeeOther)
		return
	}
	var groups []string
	if groupsRaw != "" {
		for _, g := range strings.Split(groupsRaw, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
	}

	udb, _ := readUsersFile()
	rec, exists := udb.Users[u]
	rec.DisplayName = disp
	rec.Email = email
	rec.Groups = groups
	rec.Disabled = disabled

	if pass != "" {
		h, err := hashArgon2id(pass)
		if err != nil {
			http.Redirect(w, r, "/?tab=users&msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		rec.Password = h
	} else if !exists {
		http.Redirect(w, r, "/?tab=users&msg=Password+required", http.StatusSeeOther)
		return
	}
	udb.Users[u] = rec
	writeUsersFile(udb)
	http.Redirect(w, r, "/?tab=users&msg=User+saved", http.StatusSeeOther)
}

func handleUIUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		u := strings.TrimSpace(r.FormValue("username"))
		udb, _ := readUsersFile()
		delete(udb.Users, u)
		writeUsersFile(udb)
	}
	http.Redirect(w, r, "/?tab=users&msg=User+deleted", http.StatusSeeOther)
}

func handleUIRuleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/?tab=rules", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	idxStr := r.FormValue("index")
	domainRaw := strings.TrimSpace(r.FormValue("domain"))
	policy := strings.TrimSpace(r.FormValue("policy"))
	subj := strings.TrimSpace(r.FormValue("subject"))
	netsRaw := strings.TrimSpace(r.FormValue("networks"))
	res := strings.TrimSpace(r.FormValue("resources"))

	var domains []string
	for _, d := range strings.Split(domainRaw, ",") {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	rule := AccessControlRule{Policy: policy}
	if len(domains) == 1 {
		rule.Domain = domains[0]
	} else if len(domains) > 1 {
		rule.Domains = domains
	}
	if subj != "" {
		rule.Subject = subj
	}
	if netsRaw != "" {
		var nets []string
		for _, n := range strings.Split(netsRaw, ",") {
			if n = strings.TrimSpace(n); n != "" {
				nets = append(nets, n)
			}
		}
		if len(nets) == 1 {
			rule.Networks = nets[0]
		} else {
			rule.Networks = nets
		}
	}
	if res != "" {
		rule.Resources = res
	}

	rawCfg, ac, _ := readConfigFile()
	idx, _ := strconv.Atoi(idxStr)
	if idx >= 0 && idx < len(ac.Rules) {
		ac.Rules[idx] = rule
	} else {
		ac.Rules = append(ac.Rules, rule)
	}
	writeConfigFile(rawCfg, ac)
	http.Redirect(w, r, "/?tab=rules&msg=Rule+saved", http.StatusSeeOther)
}

func handleUIRuleMove(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idx, _ := strconv.Atoi(r.FormValue("index"))
		dir := r.FormValue("direction")
		rawCfg, ac, _ := readConfigFile()
		target := idx - 1
		if dir == "down" {
			target = idx + 1
		}
		if idx >= 0 && target >= 0 && idx < len(ac.Rules) && target < len(ac.Rules) {
			ac.Rules[idx], ac.Rules[target] = ac.Rules[target], ac.Rules[idx]
			writeConfigFile(rawCfg, ac)
		}
	}
	http.Redirect(w, r, "/?tab=rules", http.StatusSeeOther)
}

func handleUIRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idx, _ := strconv.Atoi(r.FormValue("index"))
		rawCfg, ac, _ := readConfigFile()
		if idx >= 0 && idx < len(ac.Rules) {
			ac.Rules = append(ac.Rules[:idx], ac.Rules[idx+1:]...)
			writeConfigFile(rawCfg, ac)
		}
	}
	http.Redirect(w, r, "/?tab=rules&msg=Rule+deleted", http.StatusSeeOther)
}

func handleUISessionDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		key := r.FormValue("key")
		if key != "" {
			if db, err := sql.Open("sqlite", "file:"+dbPath+"?_journal=WAL"); err == nil {
				defer db.Close()
				for _, tbl := range []string{"session", "sessions", "authentication_sessions"} {
					db.Exec("DELETE FROM "+tbl+" WHERE key = ?", key)
				}
			}
		}
	}
	http.Redirect(w, r, "/?tab=sessions&msg=Session+terminated", http.StatusSeeOther)
}
