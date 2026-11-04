package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"sort"
	"strings"
)

func renderGroupsTab(w http.ResponseWriter, currentTab, msg string) {
	renderHeader(w, currentTab, msg)
	groups, _ := getGroupsList()
	udb, _ := readUsersFile()

	userNames := make([]string, 0, len(udb.Users))
	for u := range udb.Users {
		userNames = append(userNames, u)
	}
	sort.Strings(userNames)

	var userOptions strings.Builder
	for _, u := range userNames {
		userOptions.WriteString(fmt.Sprintf(`<option value="%s">%s (%s)</option>`,
			html.EscapeString(u), html.EscapeString(u), html.EscapeString(udb.Users[u].DisplayName)))
	}

	fmt.Fprintf(w, `
<h2>User Groups</h2>
<p style="color:#555;">Groups are parsed and assigned across users in <code>%s</code>.</p>

<fieldset>
  <legend>Add / Assign Group</legend>
  <form action="/groups/add" method="POST">
    <div class="form-row">
      <label>Group Name:</label>
      <input type="text" name="name" required placeholder="e.g. admins, dev, ops" style="width:240px;">
    </div>
    <div class="form-row">
      <label>Assign Users:</label>
      <select name="users" multiple size="4" style="width:240px;vertical-align:top;">
        %s
      </select>
      <span style="font-size:11px;color:#666;margin-left:6px;vertical-align:top;">(Hold Ctrl/Cmd to select multiple)</span>
    </div>
    <div class="form-row"><label></label><button type="submit" class="btn-primary">Add Group</button></div>
  </form>
</fieldset>

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
  <tbody>`, html.EscapeString(usersPath), userOptions.String())

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

func handleUIGroupAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		name := strings.TrimSpace(r.FormValue("name"))
		users := r.Form["users"]
		if name != "" {
			err := addGroupToUsers(name, users)
			if err != nil {
				log.Printf("[groups] Error adding group %q: %v", name, err)
				http.Redirect(w, r, "/?tab=groups&msg=Error+adding+group", http.StatusSeeOther)
				return
			}
			log.Printf("[groups] Group %q added/assigned to %d users by %s", name, len(users), r.RemoteAddr)
			http.Redirect(w, r, "/?tab=groups&msg=Group+added", http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/?tab=groups", http.StatusSeeOther)
}

func handleUIGroupRename(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		oldN := strings.TrimSpace(r.FormValue("old_name"))
		newN := strings.TrimSpace(r.FormValue("new_name"))
		if oldN != "" && newN != "" {
			renameGroupInUsers(oldN, newN)
			log.Printf("[groups] Group renamed from %q to %q by %s", oldN, newN, r.RemoteAddr)
		}
	}
	http.Redirect(w, r, "/?tab=groups&msg=Group+renamed", http.StatusSeeOther)
}

func handleUIGroupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		n := strings.TrimSpace(r.FormValue("name"))
		if n != "" {
			deleteGroupInUsers(n)
			log.Printf("[groups] Group %q deleted across users by %s", n, r.RemoteAddr)
		}
	}
	http.Redirect(w, r, "/?tab=groups&msg=Group+deleted", http.StatusSeeOther)
}
