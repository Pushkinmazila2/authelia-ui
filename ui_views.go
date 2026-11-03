package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func queryStatus() AutheliaStatus {
	st := AutheliaStatus{}
	if _, err := os.Stat(configPath); err == nil {
		st.ConfigFound = true
	}
	if _, err := os.Stat(usersPath); err == nil {
		st.UsersDBFound = true
	}
	if fi, err := os.Stat(dbPath); err == nil {
		st.DBFound = true
		st.DBSize = fi.Size()
	}

	if raw, _, err := readConfigFile(); err == nil {
		if jwt, ok := raw["jwt_secret"].(string); ok {
			st.JWTStrength = evaluateSecretStrength(jwt)
		} else {
			st.JWTStrength = "MISSING"
		}
		st.EncKeyStrength = "MISSING"
		if storage, ok := raw["storage"].(map[string]interface{}); ok {
			if enc, ok := storage["encryption_key"].(string); ok {
				st.EncKeyStrength = evaluateSecretStrength(enc)
			}
		}
		if server, ok := raw["server"].(map[string]interface{}); ok {
			if tls, ok := server["tls"].(map[string]interface{}); ok {
				if cert, ok := tls["certificate"].(string); ok && cert != "" {
					st.TLSConfigured = true
				}
			}
		}
	}

	if data, err := os.ReadFile(notificationPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		st.NotificationLines = strings.Join(lines, "\n")
	}

	if guardURL != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		if resp, err := client.Get(guardURL + "/api/guard/info"); err == nil {
			defer resp.Body.Close()
			var g GuardInfoResponse
			if err := json.NewDecoder(resp.Body).Decode(&g); err == nil {
				st.Running = g.AutheliaRunning
				st.ContainerName = g.AutheliaContainer
				st.ContainerImage = g.AutheliaImage
				st.Uptime = g.AutheliaUptime
				st.HostConfigPath = g.HostConfigPath
			}
		}
	} else if _, err := os.Stat(dockerSocket); err == nil {
		c := unixDialer()
		if cid, err := findTargetContainer(c); err == nil {
			st.Running = true
			st.ContainerName = cid[:12]
		}
	}
	return st
}

func renderHeader(w io.Writer, currentTab, msg string) {
	logoutLink := ""
	if uiPassword != "" {
		logoutLink = `<a href="/logout" style="float:right;color:#c00;">[Logout]</a>`
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authelia Console</title>
<style>
body { font-family: monospace, sans-serif; margin: 16px; background: #fafafa; color: #111; line-height: 1.4; font-size: 13px; }
h1, h2, h3 { margin: 8px 0; font-family: monospace; }
a { color: #0033cc; text-decoration: none; }
a:hover { text-decoration: underline; }
.nav { margin-bottom: 16px; border-bottom: 2px solid #222; padding-bottom: 6px; }
.nav a { margin-right: 12px; font-weight: bold; padding: 4px 8px; }
.nav a.active { background: #222; color: #fff; text-decoration: none; }
table { border-collapse: collapse; width: 100%%; margin: 12px 0; font-size: 12px; }
th, td { border: 1px solid #bbb; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #eee; }
tr:nth-child(even) { background: #f2f2f2; }
input, select, textarea, button { font-family: monospace; font-size: 12px; padding: 3px 6px; }
button { cursor: pointer; background: #e0e0e0; border: 1px solid #888; border-radius: 2px; }
button:hover { background: #ccc; }
.btn-danger { background: #ffe6e6; color: #900; border-color: #c00; }
.btn-primary { background: #0033cc; color: #fff; border-color: #002299; font-weight: bold; }
.badge { display: inline-block; padding: 1px 5px; font-size: 11px; border-radius: 2px; font-weight: bold; border: 1px solid #888; }
.badge-ok { background: #d4edda; color: #155724; border-color: #c3e6cb; }
.badge-warn { background: #fff3cd; color: #856404; border-color: #ffeeba; }
.badge-err { background: #f8d7da; color: #721c24; border-color: #f5c6cb; }
.msg-banner { background: #d1ecf1; color: #0c5460; padding: 6px 10px; margin-bottom: 12px; border: 1px solid #bee5eb; }
pre { background: #eee; border: 1px solid #ccc; padding: 8px; font-size: 11px; overflow-x: auto; max-height: 480px; }
fieldset { border: 1px solid #aaa; margin: 12px 0; padding: 8px 12px; background: #fff; }
legend { font-weight: bold; padding: 0 4px; }
.form-row { margin-bottom: 6px; }
.form-row label { display: inline-block; width: 150px; font-weight: bold; }
</style>
</head>
<body>
<h1>[Authelia Console]</h1>
<div class="nav">
  <a href="/?tab=dashboard" class="%s">Dashboard</a>
  <a href="/?tab=users" class="%s">Users</a>
  <a href="/?tab=groups" class="%s">Groups</a>
  <a href="/?tab=clients" class="%s">OIDC Clients</a>
  <a href="/?tab=rules" class="%s">Access Rules</a>
  <a href="/?tab=sessions" class="%s">Sessions</a>
  <a href="/?tab=logs" class="%s">Logs</a>
  %s
</div>
`,
		act(currentTab == "dashboard"),
		act(currentTab == "users"),
		act(currentTab == "groups"),
		act(currentTab == "clients"),
		act(currentTab == "rules"),
		act(currentTab == "sessions"),
		act(currentTab == "logs"),
		logoutLink,
	)
	if msg != "" {
		fmt.Fprintf(w, `<div class="msg-banner">%s</div>`, html.EscapeString(msg))
	}
}

func act(c bool) string {
	if c {
		return "active"
	}
	return ""
}

func renderFooter(w io.Writer) {
	fmt.Fprintf(w, `<hr style="margin-top:20px;border:0;border-top:1px solid #ccc;"><div style="font-size:11px;color:#777;">Authelia UI Engineering Edition | Minimalist Pure HTML | No JS</div></body></html>`)
}
