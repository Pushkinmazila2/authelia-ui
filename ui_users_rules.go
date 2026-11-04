package main

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	_ "modernc.org/sqlite"
)

func renderUsersTab(w http.ResponseWriter, currentTab, msg, editUsername string) {
	renderHeader(w, currentTab, msg)
	udb, _ := readUsersFile()
	existingGroups, _ := getGroupsList()

	editUser := UserRecord{}
	isEdit := false
	if editUsername != "" {
		if u, ok := udb.Users[editUsername]; ok {
			editUser = u
			isEdit = true
		}
	}
	title := "Add User"
	btn := "Create"
	ro := ""
	ph := "Password"
	if isEdit {
		title = "Edit: " + html.EscapeString(editUsername)
		btn = "Save"
		ro = "readonly"
		ph = "Leave blank to keep"
	}
	ch := ""
	if editUser.Disabled {
		ch = "checked"
	}

	userGroupMap := make(map[string]bool)
	for _, g := range editUser.Groups {
		userGroupMap[strings.TrimSpace(g)] = true
	}

	var groupOptions strings.Builder
	if len(existingGroups) == 0 {
		groupOptions.WriteString(`<option value="" disabled>(No groups created yet - enter below)</option>`)
	} else {
		for _, g := range existingGroups {
			selected := ""
			if userGroupMap[g.Name] {
				selected = "selected"
			}
			groupOptions.WriteString(fmt.Sprintf(`<option value="%s" %s>%s (%d members)</option>`,
				html.EscapeString(g.Name), selected, html.EscapeString(g.Name), g.Count))
		}
	}

	fmt.Fprintf(w, `
<h2>Users (<code>%s</code>)</h2>
<fieldset>
  <legend>%s</legend>
  <form action="/users/save" method="POST">
    <div class="form-row"><label>Username:</label><input type="text" name="username" value="%s" %s required></div>
    <div class="form-row"><label>Display Name:</label><input type="text" name="displayname" value="%s" required style="width:240px;"></div>
    <div class="form-row"><label>Email:</label><input type="email" name="email" value="%s" required style="width:240px;"></div>
    <div class="form-row">
      <label>Groups (Select):</label>
      <select name="groups" multiple size="4" style="width:240px;vertical-align:top;">
        %s
      </select>
      <span style="font-size:11px;color:#666;margin-left:6px;vertical-align:top;">(Hold Ctrl/Cmd to select multiple)</span>
    </div>
    <div class="form-row">
      <label>New Group (Optional):</label>
      <input type="text" name="new_group" placeholder="Type new group name if not in list" style="width:240px;">
    </div>
    <div class="form-row"><label>Password:</label><input type="password" name="password" style="width:240px;" placeholder="%s"></div>
    <div class="form-row"><label>Disabled:</label><input type="checkbox" name="disabled" value="1" %s></div>
    <div class="form-row"><label></label><button type="submit" class="btn-primary">%s</button> %s</div>
  </form>
</fieldset>
<table>
  <thead><tr><th>Username</th><th>Display Name</th><th>Email</th><th>Groups</th><th>Status</th><th>Actions</th></tr></thead>
  <tbody>`,
		html.EscapeString(usersPath), title,
		html.EscapeString(editUsername), ro,
		html.EscapeString(editUser.DisplayName),
		html.EscapeString(editUser.Email),
		groupOptions.String(),
		ph, ch, btn, cancelLink(isEdit, "/?tab=users"),
	)

	names := make([]string, 0, len(udb.Users))
	for n := range udb.Users {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := udb.Users[n]
		st := `<span class="badge badge-ok">ACTIVE</span>`
		if u.Disabled {
			st = `<span class="badge badge-err">DISABLED</span>`
		}
		fmt.Fprintf(w, `<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>
<a href="/?tab=users&edit=%s">Edit</a> |
<form action="/users/delete" method="POST" style="display:inline;" onsubmit="return confirm('Delete %s?');">
<input type="hidden" name="username" value="%s"><button type="submit" class="btn-danger" style="padding:1px 4px;font-size:11px;">Del</button></form>
</td></tr>`,
			html.EscapeString(n), html.EscapeString(u.DisplayName), html.EscapeString(u.Email),
			html.EscapeString(strings.Join(u.Groups, ", ")), st, url.QueryEscape(n),
			html.EscapeString(n), html.EscapeString(n),
		)
	}
	if len(names) == 0 {
		fmt.Fprintf(w, `<tr><td colspan="6" style="text-align:center;color:#666;">No users defined.</td></tr>`)
	}
	fmt.Fprintf(w, `</tbody></table>`)
	renderFooter(w)
}

func cancelLink(isEdit bool, dest string) string {
	if isEdit {
		return fmt.Sprintf(`&nbsp;<a href="%s">Cancel</a>`, dest)
	}
	return ""
}
