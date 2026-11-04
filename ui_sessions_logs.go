package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func renderSessionsTab(w http.ResponseWriter, currentTab, msg string) {
	renderHeader(w, currentTab, msg)
	fmt.Fprintf(w, `<h2>Active SQLite Sessions (<code>%s</code>)</h2>`, html.EscapeString(dbPath))
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		fmt.Fprintf(w, `<p>Database not available.</p>`)
		renderFooter(w)
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
	fmt.Fprintf(w, `<table><thead><tr><th>Session Key</th><th>Expiry</th><th>Action</th></tr></thead><tbody>`)
	for _, s := range list {
		fmt.Fprintf(w, `<tr><td><code>%s</code></td><td>%s</td><td>
<form action="/sessions/delete" method="POST" onsubmit="return confirm('Terminate session?');">
<input type="hidden" name="key" value="%s"><button type="submit" class="btn-danger" style="font-size:11px;">Terminate</button></form></td></tr>`,
			html.EscapeString(s.Key), html.EscapeString(s.Exp), html.EscapeString(s.Key),
		)
	}
	if len(list) == 0 {
		fmt.Fprintf(w, `<tr><td colspan="3" style="text-align:center;color:#666;">No active sessions found.</td></tr>`)
	}
	fmt.Fprintf(w, `</tbody></table>`)
	renderFooter(w)
}

func renderLogsTab(w http.ResponseWriter, currentTab, msg, tail string) {
	renderHeader(w, currentTab, msg)
	if tail == "" {
		tail = "200"
	}
	logs := "No logs available."
	source := "Unavailable"

	if guardURL != "" {
		source = "Docker Guard (" + guardURL + ")"
		c := &http.Client{Timeout: 5 * time.Second}
		if resp, err := c.Get(guardURL + "/api/guard/logs?tail=" + tail); err == nil {
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			logs = string(b)
		} else {
			logs = fmt.Sprintf("Error contacting Docker Guard: %v", err)
		}
	} else if _, err := os.Stat(dockerSocket); err == nil {
		source = "Direct Docker Socket (" + dockerSocket + ")"
		c := unixDialer()
		if cid, err := findTargetContainer(c); err == nil {
			source += fmt.Sprintf(" [Target: %s]", cid[:12])
			if resp, err := c.Get("http://localhost/containers/" + cid + "/logs?stdout=true&stderr=true&tail=" + tail + "&timestamps=true"); err == nil {
				defer resp.Body.Close()
				var sb strings.Builder
				sc := bufio.NewScanner(resp.Body)
				for sc.Scan() {
					l := sc.Bytes()
					if len(l) > 8 {
						l = l[8:]
					}
					sb.Write(l)
					sb.WriteByte('\n')
				}
				logs = sb.String()
			} else {
				logs = fmt.Sprintf("Error fetching container logs: %v", err)
			}
		} else {
			logs = fmt.Sprintf("Authelia container not found via socket: %v", err)
		}
	}

	fmt.Fprintf(w, `
<h2>Authelia Logs</h2>
<div style="margin-bottom:12px;">
  <strong>Source:</strong> <code>%s</code> &nbsp;|&nbsp;
  <strong>Tail Lines:</strong> 
  <a href="/?tab=logs&tail=100" class="btn-primary" style="padding:1px 5px;font-size:11px;">100</a>
  <a href="/?tab=logs&tail=200" class="btn-primary" style="padding:1px 5px;font-size:11px;">200</a>
  <a href="/?tab=logs&tail=500" class="btn-primary" style="padding:1px 5px;font-size:11px;">500</a>
  <a href="/?tab=logs&tail=1000" class="btn-primary" style="padding:1px 5px;font-size:11px;">1000</a>
  &nbsp;&nbsp;
  <a href="/?tab=logs&tail=%s" class="btn-primary" style="padding:2px 8px;">Refresh</a>
</div>
<pre style="background:#0f172a;color:#94a3b8;font-size:11px;height:520px;overflow-y:scroll;line-height:1.3;padding:10px;">%s</pre>
`, html.EscapeString(source), html.EscapeString(tail), html.EscapeString(logs))
	renderFooter(w)
}
