package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func renderUsersTab(w http.ResponseWriter, currentTab, msg, editUsername string) {
	renderHeader(w, currentTab, msg)
	udb, _ := readUsersFile()
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

	fmt.Fprintf(w, `
<h2>Users (<code>%s</code>)</h2>
<fieldset>
  <legend>%s</legend>
  <form action="/users/save" method="POST">
    <div class="form-row"><label>Username:</label><input type="text" name="username" value="%s" %s required></div>
    <div class="form-row"><label>Display Name:</label><input type="text" name="displayname" value="%s" required style="width:240px;"></div>
    <div class="form-row"><label>Email:</label><input type="email" name="email" value="%s" required style="width:240px;"></div>
    <div class="form-row"><label>Groups:</label><input type="text" name="groups" value="%s" style="width:240px;" placeholder="admin, dev"></div>
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
		html.EscapeString(strings.Join(editUser.Groups, ", ")),
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
