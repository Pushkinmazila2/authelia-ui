package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
	apiToken      = strings.TrimSpace(strings.Trim(os.Getenv("API_TOKEN"), "\"'"))
	uiUser        = strings.TrimSpace(strings.Trim(getEnv("UI_USER", "admin"), "\"'"))
	uiPassword    = strings.TrimSpace(strings.Trim(getEnv("UI_PASSWORD", ""), "\"'"))
	sessionSecret = getEnv("SESSION_SECRET", "authelia-ui-secret-key-change-me")
)

func init() {
	if apiToken == "" {
		log.Println("[security] API_TOKEN is empty. /api endpoints will reject requests.")
	}
	if uiPassword == "" {
		log.Println("[security] UI_PASSWORD is not set. UI authentication is disabled.")
	} else {
		log.Printf("[security] UI auth enabled. Expected user: %q, expected password length: %d", uiUser, len(uiPassword))
	}
}

func apiAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiToken == "" {
			http.Error(w, `{"error":"unauthorized: API_TOKEN not set"}`, 401)
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
		token = strings.TrimSpace(token)
		if subtle.ConstantTimeCompare([]byte(token), []byte(apiToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthorized: invalid token"}`))
			return
		}
		next(w, r)
	}
}

func signCookie(username string, exp int64) string {
	payload := fmt.Sprintf("%s:%d", username, exp)
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	raw := fmt.Sprintf("%s:%s", payload, sig)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func verifyCookie(cookieVal string) bool {
	rawBytes, err := base64.RawURLEncoding.DecodeString(cookieVal)
	if err != nil {
		return false
	}
	parts := strings.Split(string(rawBytes), ":")
	if len(parts) != 3 {
		return false
	}
	username, expStr, sig := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	payload := fmt.Sprintf("%s:%d", username, exp)
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) == 1
}

func uiAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if uiPassword == "" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("authelia_ui_session")
		if err == nil && verifyCookie(cookie.Value) {
			next(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cookie, err := r.Cookie("authelia_ui_session")
		if err == nil && verifyCookie(cookie.Value) {
			http.Redirect(w, r, "/?tab=dashboard", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		errMsg := ""
		if r.URL.Query().Get("err") != "" {
			errMsg = `<div style="color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;padding:6px;margin-bottom:10px;font-size:12px;">Invalid credentials.</div>`
		}
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authelia UI Login</title>
<style>body{font-family:monospace;background:#fafafa;margin:60px auto;max-width:320px;font-size:13px;}
fieldset{border:1px solid #999;padding:14px;background:#fff;}input{width:90%%;padding:5px;margin:4px 0 10px;font-family:monospace;}
button{width:95%%;padding:6px;background:#0033cc;color:#fff;border:1px solid #002299;font-weight:bold;cursor:pointer;font-family:monospace;}
</style></head><body><fieldset><legend>[Authelia UI Login]</legend>%s
<form action="/login" method="POST">
<label>Username:</label><input type="text" name="username" value="%s" required autofocus>
<label>Password:</label><input type="password" name="password" required>
<button type="submit">Sign In</button>
</form></fieldset></body></html>`, errMsg, strings.ReplaceAll(uiUser, `"`, `&quot;`))
		return
	}

	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		rawPass := r.FormValue("password")
		cleanPass := strings.TrimSpace(strings.Trim(rawPass, "\r\n\"'"))
		cleanExpectedPass := strings.TrimSpace(strings.Trim(uiPassword, "\r\n\"'"))

		userMatch := (uiUser == "") || strings.EqualFold(user, uiUser)
		passMatch := (cleanExpectedPass != "") && (rawPass == uiPassword || cleanPass == cleanExpectedPass)

		if userMatch && passMatch {
			log.Printf("[auth] Login successful for user: %q", user)
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
			http.Redirect(w, r, "/?tab=dashboard", http.StatusFound)
			return
		}

		log.Printf("[auth] Login failed: user=%q (expected %q, match=%t), received_pass_len=%d, expected_pass_len=%d",
			user, uiUser, userMatch, len(cleanPass), len(cleanExpectedPass))
		http.Redirect(w, r, "/login?err=1", http.StatusFound)
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
	http.Redirect(w, r, "/login", http.StatusFound)
}

