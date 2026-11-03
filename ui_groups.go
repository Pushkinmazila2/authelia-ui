package main

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
)

func renderGroupsTab(w http.ResponseWriter, currentTab, msg string) {
	renderHeader(w, currentTab, msg)
	groups, _ := getGroupsList()

	fmt.Fprintf(w, `
<h2>User Groups</h2>
<p style="color:#555;">Groups are parsed and assigned across users in <code>%s</code>.</p>

<fieldset>
  <legend>Rename Group</legend>
  <form action="/groups/rename" method="POST">
    <div class="form-row"><label>Current Name:</label><input type="text" name="old_name" required placeholder="dev"></div>
    <div class="form-row"><label>New Name:</label><input type="text" name="new_name" required placeholder="developers"></div>
    <div class="form-row"><label></label><button type="submit" class="btn-primary">Rename Group</button></div>
  </form>
</fieldset>

<table>
  <thead><tr><th>Group Name</th><th>Members Count</th><th>Members</th><th>Actions</th></tr></thead>
  <tbody>`, html.EscapeString(usersPath))

	for _, g := range groups {
		membersStr := strings.Join(g.Members, ", ")
		fmt.Fprintf(w, `<tr>
  <td><strong>%s</strong></td>
  <td>%d</td>
  <td>%s</td>
  <td>
    <form action="/groups/delete" method="POST" style="display:inline;" onsubmit="return confirm('Remove group %s from all users?');">
      <input type="hidden" name="name" value="%s">
      <button type="submit" class="btn-danger" style="font-size:11px;">Delete</button>
    </form>
  </td>
</tr>`,
			html.EscapeString(g.Name), g.Count, html.EscapeString(membersStr),
			html.EscapeString(g.Name), html.EscapeString(g.Name),
		)
	}

	if len(groups) == 0 {
		fmt.Fprintf(w, `<tr><td colspan="4" style="text-align:center;color:#666;">No groups assigned to any user.</td></tr>`)
	}

	fmt.Fprintf(w, `</tbody></table>`)
	renderFooter(w)
}

func handleUIGroupRename(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		oldN := strings.TrimSpace(r.FormValue("old_name"))
		newN := strings.TrimSpace(r.FormValue("new_name"))
		if oldN != "" && newN != "" {
			renameGroupInUsers(oldN, newN)
		}
	}
	http.Redirect(w, r, "/?tab=groups&msg=Group+renamed", http.StatusSeeOther)
}

func handleUIGroupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		n := strings.TrimSpace(r.FormValue("name"))
		if n != "" {
			deleteGroupInUsers(n)
		}
	}
	http.Redirect(w, r, "/?tab=groups&msg=Group+deleted", http.StatusSeeOther)
}
