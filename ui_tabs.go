package main

import (
	"fmt"
	"html"
	"net/http"
	_ "modernc.org/sqlite"
)

func handleUIRoute(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "dashboard"
	}
	msg := r.URL.Query().Get("msg")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch tab {
	case "users":
		renderUsersTab(w, tab, msg, r.URL.Query().Get("edit"))
	case "groups":
		renderGroupsTab(w, tab, msg)
	case "clients":
		renderClientsTab(w, tab, msg, r.URL.Query().Get("secret"))
	case "rules":
		renderRulesTab(w, tab, msg, r.URL.Query().Get("edit"))
	case "sessions":
		renderSessionsTab(w, tab, msg)
	case "logs":
		renderLogsTab(w, tab, msg, r.URL.Query().Get("tail"))
	default:
		renderDashboardTab(w, tab, msg)
	}
}

func renderDashboardTab(w http.ResponseWriter, currentTab, msg string) {
	renderHeader(w, currentTab, msg)
	st := queryStatus()
	runBadge := `<span class="badge badge-err">STOPPED</span>`
	if st.Running {
		runBadge = `<span class="badge badge-ok">RUNNING</span>`
	}
	healthBadge := ""
	if st.ContainerHealth != "" {
		if strings.Contains(strings.ToLower(st.ContainerHealth), "healthy") {
			healthBadge = fmt.Sprintf(`<span class="badge badge-ok">%s</span>`, html.EscapeString(st.ContainerHealth))
		} else {
			healthBadge = fmt.Sprintf(`<span class="badge badge-warn">%s</span>`, html.EscapeString(st.ContainerHealth))
		}
	}
	hostPath := "Direct mount"
	if st.HostConfigPath != "" {
		hostPath = "Host: " + html.EscapeString(st.HostConfigPath)
	}

	mountsSummary := ""
	if len(st.Mounts) > 0 {
		var ms []string
		for dst, src := range st.Mounts {
			ms = append(ms, fmt.Sprintf("<code>%s</code> &rarr; <code>%s</code>", html.EscapeString(src), html.EscapeString(dst)))
		}
		mountsSummary = strings.Join(ms, "<br>")
	} else {
		mountsSummary = "None detected"
	}

	containerIP := st.ContainerIP
	if containerIP == "" {
		containerIP = "N/A"
	}

	fmt.Fprintf(w, `
<h2>System Status</h2>
<table>
  <tr><th style="width:200px;">Authelia Container</th><td>%s %s <strong>%s</strong> (Uptime: %s, Restarts: %d, IP: %s)</td></tr>
  <tr><th>Container Image</th><td><code>%s</code></td></tr>
  <tr><th>Container Mounts</th><td>%s</td></tr>
  <tr><th>Config Location</th><td>%s (Local: <code>%s</code>)</td></tr>
  <tr><th>users_database.yml</th><td>%s (<code>%s</code>)</td></tr>
  <tr><th>db.sqlite3</th><td>%s (%d bytes, <code>%s</code>)</td></tr>
  <tr><th>TLS / HTTPS</th><td>%s</td></tr>
  <tr><th>JWT Secret</th><td><strong>%s</strong></td></tr>
  <tr><th>Encryption Key</th><td><strong>%s</strong></td></tr>
</table>
<fieldset>
  <legend>Actions</legend>
  <form action="/restart" method="POST" style="display:inline;">
    <button type="submit" class="btn-primary" onclick="return confirm('Restart Authelia?');">Restart Authelia</button>
  </form>
</fieldset>
<h3>Recent Notification Output</h3>
<pre>%s</pre>
`,
		runBadge, healthBadge, html.EscapeString(st.ContainerName), html.EscapeString(st.Uptime), st.ContainerRestartCount, html.EscapeString(containerIP),
		html.EscapeString(st.ContainerImage),
		mountsSummary,
		hostPath, html.EscapeString(configPath),
		badge(st.UsersDBFound), html.EscapeString(usersPath),
		badge(st.DBFound), st.DBSize, html.EscapeString(dbPath),
		tlsBadge(st.TLSConfigured),
		html.EscapeString(st.JWTStrength),
		html.EscapeString(st.EncKeyStrength),
		html.EscapeString(st.NotificationLines),
	)
	renderFooter(w)
}

func badge(found bool) string {
	if found {
		return `<span class="badge badge-ok">EXISTS</span>`
	}
	return `<span class="badge badge-err">MISSING</span>`
}

func tlsBadge(c bool) string {
	if c {
		return `<span class="badge badge-ok">TLS ON</span>`
	}
	return `<span class="badge badge-warn">NO TLS</span>`
}
