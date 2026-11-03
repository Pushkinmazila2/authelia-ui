package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	apiToken      = os.Getenv("API_TOKEN")
	uiUser        = getEnv("UI_USER", "")
	uiPassword    = getEnv("UI_PASSWORD", "")
	sessionSecret = getEnv("SESSION_SECRET", "authelia-ui-secret-key-change-me")
)

func init() {
	if apiToken == "" {
		log.Println("[security] WARNING: API_TOKEN is empty. /api endpoints will reject requests until API_TOKEN is set.")
	}
	if uiPassword == "" {
		log.Println("[security] NOTICE: UI_PASSWORD is not set. UI authentication is disabled.")
	}
}

// -----------------------------------------------------------------------------
// API BEARER TOKEN MIDDLEWARE
// -----------------------------------------------------------------------------

func apiAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiToken == "" {
			http.Error(w, `{"error":"unauthorized: API_TOKEN not configured on server"}`, http.StatusUnauthorized)
			return
		}
		authHdr := r.Header.Get("Authorization")
		token := ""
		if strings.HasPrefix(authHdr, "Bearer ") {
			token = strings.TrimPrefix(authHdr, "Bearer ")
		} else if strings.HasPrefix(authHdr, "Token ") {
			token = strings.TrimPrefix(authHdr, "Token ")
		} else if xKey := r.Header.Get("X-API-Key"); xKey != "" {
			token = xKey
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(apiToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized: invalid or missing bearer token"}`))
			return
		}
		next(w, r)
	}
}

// -----------------------------------------------------------------------------
// UI COOKIE AUTHENTICATION
// -----------------------------------------------------------------------------

func signCookie(username string, exp int64) string {
	payload := fmt.Sprintf("%s:%d", username, exp)
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s:%s", payload, sig)
}

func verifyCookie(cookieVal string) bool {
	parts := strings.Split(cookieVal, ":")
	if len(parts) != 3 {
		return false
	}
	username, expStr, sig := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	expectedSig := signCookie(username, exp)
	return subtle.ConstantTimeCompare([]byte(cookieVal), []byte(expectedSig)) == 1
}

func uiAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If UI_PASSWORD is not set, auth is disabled
		if uiPassword == "" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("authelia_ui_session")
		if err == nil && verifyCookie(cookie.Value) {
			next(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		errMsg := ""
		if r.URL.Query().Get("err") != "" {
			errMsg = `<div style="color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;padding:6px 10px;margin-bottom:12px;font-size:12px;">Invalid username or password.</div>`
		}
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Authelia Console - Login</title>
<style>
body { font-family: monospace, sans-serif; background: #fafafa; margin: 40px auto; max-width: 320px; line-height: 1.5; }
fieldset { border: 1px solid #bbb; padding: 14px; background: #fff; }
legend { font-weight: bold; }
input { width: 95%%; padding: 5px; margin: 4px 0 12px; font-family: monospace; font-size: 13px; }
button { width: 100%%; padding: 6px; background: #0033cc; color: #fff; border: 1px solid #002299; font-weight: bold; cursor: pointer; font-family: monospace; }
</style>
</head>
<body>
<fieldset>
  <legend>[Authelia UI Login]</legend>
  %s
  <form action="/login" method="POST">
    <label>Username:</label>
    <input type="text" name="username" required autofocus>
    <label>Password:</label>
    <input type="password" name="password" required>
    <button type="submit">Sign In</button>
  </form>
</fieldset>
</body>
</html>`, errMsg)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")

		userMatch := uiUser == "" || subtle.ConstantTimeCompare([]byte(user), []byte(uiUser)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(uiPassword)) == 1

		if userMatch && passMatch {
			exp := time.Now().Add(24 * time.Hour).Unix()
			val := signCookie(user, exp)
			http.SetCookie(w, &http.Cookie{
				Name:     "authelia_ui_session",
				Value:    val,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
			http.Redirect(w, r, "/?tab=dashboard", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login?err=1", http.StatusSeeOther)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "authelia_ui_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
