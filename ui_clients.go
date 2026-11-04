package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func renderClientsTab(w http.ResponseWriter, currentTab, msg, secretMsg string) {
	renderHeader(w, currentTab, msg)
	clients, _ := readOIDCClients()

	if secretMsg != "" {
		fmt.Fprintf(w, `<div style="background:#fff3cd;color:#856404;border:1px solid #ffeeba;padding:8px 12px;margin-bottom:12px;">
<strong>IMPORTANT: Generated Raw Client Secret:</strong><br>
<code style="font-size:14px;background:#fff;padding:2px 6px;">%s</code><br>
Save this secret now! Authelia stores it as an Argon2id hash and it cannot be displayed again.
</div>`, html.EscapeString(secretMsg))
	}

	fmt.Fprintf(w, `
<h2>OIDC / OAuth 2.0 Clients</h2>
<p style="color:#555;">Managed in <code>%s</code> under <code>identity_providers.oidc.clients</code>.</p>

<fieldset>
  <legend>Register New OIDC Client</legend>
  <form action="/clients/save" method="POST">
    <div class="form-row"><label>Client ID:</label><input type="text" name="id" required placeholder="my-app" style="width:280px;"></div>
    <div class="form-row"><label>Description:</label><input type="text" name="description" placeholder="My Web Application" style="width:280px;"></div>
    <div class="form-row"><label>Client Secret:</label><input type="text" name="secret" placeholder="Leave empty to auto-generate" style="width:280px;"></div>
    <div class="form-row"><label>Policy:</label><select name="policy">
      <option value="two_factor">two_factor</option>
      <option value="one_factor">one_factor</option>
      <option value="bypass">bypass</option>
    </select></div>
    <div class="form-row"><label>Redirect URIs:</label><input type="text" name="redirect_uris" required placeholder="https://app.example.com/oauth/callback" style="width:360px;"></div>
    <div class="form-row"><label>Scopes:</label><input type="text" name="scopes" value="openid, profile, email, groups" style="width:360px;"></div>
    <div class="form-row"><label>Public Client:</label><input type="checkbox" name="public" value="1"> (No secret required)</div>
    <div class="form-row"><label></label><button type="submit" class="btn-primary">Register Client</button></div>
  </form>
</fieldset>

<table>
  <thead><tr><th>Client ID</th><th>Description</th><th>Policy</th><th>Public</th><th>Redirect URIs</th><th>Scopes</th><th>Action</th></tr></thead>
  <tbody>`, html.EscapeString(configPath))

	for _, c := range clients {
		uris := strings.Join(c.RedirectURIs, ", ")
		scopes := strings.Join(c.Scopes, ", ")
		isPublic := "No"
		if c.Public {
			isPublic = "Yes"
		}
		fmt.Fprintf(w, `<tr>
  <td><strong>%s</strong></td>
  <td>%s</td>
  <td><span class="badge badge-ok">%s</span></td>
  <td>%s</td>
  <td><code>%s</code></td>
  <td>%s</td>
  <td>
    <form action="/clients/delete" method="POST" onsubmit="return confirm('Delete client %s?');">
      <input type="hidden" name="id" value="%s">
      <button type="submit" class="btn-danger" style="font-size:11px;">Delete</button>
    </form>
  </td>
</tr>`,
			html.EscapeString(c.ID), html.EscapeString(c.Description),
			html.EscapeString(c.AuthorizationPolicy), isPublic,
			html.EscapeString(uris), html.EscapeString(scopes),
			html.EscapeString(c.ID), html.EscapeString(c.ID),
		)
	}

	if len(clients) == 0 {
		fmt.Fprintf(w, `<tr><td colspan="7" style="text-align:center;color:#666;">No OIDC clients configured.</td></tr>`)
	}

	fmt.Fprintf(w, `</tbody></table>`)
	renderFooter(w)
}

func handleUIClientSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/?tab=clients", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	desc := strings.TrimSpace(r.FormValue("description"))
	sec := strings.TrimSpace(r.FormValue("secret"))
	policy := strings.TrimSpace(r.FormValue("policy"))
	urisRaw := strings.TrimSpace(r.FormValue("redirect_uris"))
	scopesRaw := strings.TrimSpace(r.FormValue("scopes"))
	isPublic := r.FormValue("public") == "1"

	if id == "" {
		http.Redirect(w, r, "/?tab=clients&msg=Client+ID+required", http.StatusSeeOther)
		return
	}

	var uris []string
	for _, u := range strings.Split(urisRaw, ",") {
		if u = strings.TrimSpace(u); u != "" {
			uris = append(uris, u)
		}
	}
	var scopes []string
	for _, s := range strings.Split(scopesRaw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}

	rawSecret := ""
	hashedSecret := ""
	if !isPublic {
		if sec == "" {
			rawSecret, _ = generateRandomSecret(24)
			hashedSecret, _ = hashArgon2id(rawSecret)
		} else if strings.HasPrefix(sec, "$argon2") {
			hashedSecret = sec
		} else {
			rawSecret = sec
			hashedSecret, _ = hashArgon2id(sec)
		}
	}

	client := OIDCClient{
		ID:                  id,
		Description:         desc,
		Secret:              hashedSecret,
		Public:              isPublic,
		AuthorizationPolicy: policy,
		RedirectURIs:        uris,
		Scopes:              scopes,
		GrantTypes:          []string{"authorization_code"},
		ResponseTypes:       []string{"code"},
	}

	clients, _ := readOIDCClients()
	clients = append(clients, client)
	if err := writeOIDCClients(clients); err != nil {
		log.Printf("[oidc] Error writing clients: %v", err)
	} else {
		log.Printf("[oidc] Client registered: %q (policy: %s, public: %v) by %s", client.ID, client.AuthorizationPolicy, client.Public, r.RemoteAddr)
	}

	redir := "/?tab=clients&msg=Client+registered"
	if rawSecret != "" {
		redir += "&secret=" + url.QueryEscape(rawSecret)
	}
	http.Redirect(w, r, redir, http.StatusSeeOther)
}

func handleUIClientDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		id := strings.TrimSpace(r.FormValue("id"))
		clients, _ := readOIDCClients()
		for i, c := range clients {
			if c.ID == id {
				clients = append(clients[:i], clients[i+1:]...)
				writeOIDCClients(clients)
				log.Printf("[oidc] Client deleted: %q by %s", id, r.RemoteAddr)
				break
			}
		}
	}
	http.Redirect(w, r, "/?tab=clients&msg=Client+deleted", http.StatusSeeOther)
}
