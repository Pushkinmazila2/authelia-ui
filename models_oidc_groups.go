package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type OIDCClient struct {
	ID                  string   `yaml:"id" json:"id"`
	Description         string   `yaml:"description,omitempty" json:"description,omitempty"`
	Secret              string   `yaml:"secret,omitempty" json:"secret,omitempty"`
	Public              bool     `yaml:"public,omitempty" json:"public,omitempty"`
	AuthorizationPolicy string   `yaml:"authorization_policy,omitempty" json:"authorization_policy,omitempty"`
	RedirectURIs        []string `yaml:"redirect_uris" json:"redirect_uris"`
	Scopes              []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	GrantTypes          []string `yaml:"grant_types,omitempty" json:"grant_types,omitempty"`
	ResponseTypes       []string `yaml:"response_types,omitempty" json:"response_types,omitempty"`
}

type GroupInfo struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	Count   int      `json:"count"`
}

func readOIDCClients() ([]OIDCClient, error) {
	raw, _, err := readConfigFile()
	if err != nil {
		return nil, err
	}

	idp, ok := raw["identity_providers"].(map[string]interface{})
	if !ok {
		return []OIDCClient{}, nil
	}
	oidc, ok := idp["oidc"].(map[string]interface{})
	if !ok {
		return []OIDCClient{}, nil
	}
	clientsRaw, ok := oidc["clients"]
	if !ok {
		return []OIDCClient{}, nil
	}

	b, err := yaml.Marshal(clientsRaw)
	if err != nil {
		return nil, err
	}
	var clients []OIDCClient
	if err := yaml.Unmarshal(b, &clients); err != nil {
		return nil, err
	}
	return clients, nil
}

func writeOIDCClients(clients []OIDCClient) error {
	raw, _, err := readConfigFile()
	if err != nil {
		return err
	}

	idp, ok := raw["identity_providers"].(map[string]interface{})
	if !ok {
		idp = make(map[string]interface{})
		raw["identity_providers"] = idp
	}
	oidc, ok := idp["oidc"].(map[string]interface{})
	if !ok {
		oidc = make(map[string]interface{})
		idp["oidc"] = oidc
	}
	oidc["clients"] = clients

	// Ensure Authelia 4.38+ compatibility: auto-generate JWKS and hmac_secret if missing
	if err := ensureOIDCSettings(oidc); err != nil {
		return err
	}

	return writeConfigFile(raw, getACFromMap(raw))
}

func ensureOIDCSettings(oidc map[string]interface{}) error {
	// 1. Ensure hmac_secret
	hmac, _ := oidc["hmac_secret"].(string)
	if hmac == "" {
		sec, err := generateRandomSecret(32)
		if err == nil {
			oidc["hmac_secret"] = sec
		}
	}

	// 2. Ensure JWKS
	jwksRaw, exists := oidc["jwks"]
	needJWKS := false
	if !exists || jwksRaw == nil {
		needJWKS = true
	} else if jwksList, ok := jwksRaw.([]interface{}); ok && len(jwksList) == 0 {
		needJWKS = true
	}

	if needJWKS {
		keyPEM, err := generateRSAPrivateKeyPEM(2048)
		if err != nil {
			return err
		}
		oidc["jwks"] = []map[string]interface{}{
			{
				"key": keyPEM,
			},
		}
	}
	return nil
}

func generateRSAPrivateKeyPEM(bits int) (string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", err
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	return string(pem.EncodeToMemory(privBlock)), nil
}

func isOIDCJWKSConfigured() bool {
	raw, _, err := readConfigFile()
	if err != nil {
		return false
	}
	idp, ok := raw["identity_providers"].(map[string]interface{})
	if !ok {
		return false
	}
	oidc, ok := idp["oidc"].(map[string]interface{})
	if !ok {
		return false
	}
	jwksRaw, exists := oidc["jwks"]
	if !exists || jwksRaw == nil {
		return false
	}
	if list, ok := jwksRaw.([]interface{}); ok && len(list) > 0 {
		return true
	}
	return false
}

func generateAndSaveOIDCJWKS() error {
	raw, _, err := readConfigFile()
	if err != nil {
		return err
	}
	idp, ok := raw["identity_providers"].(map[string]interface{})
	if !ok {
		idp = make(map[string]interface{})
		raw["identity_providers"] = idp
	}
	oidc, ok := idp["oidc"].(map[string]interface{})
	if !ok {
		oidc = make(map[string]interface{})
		idp["oidc"] = oidc
	}

	keyPEM, err := generateRSAPrivateKeyPEM(2048)
	if err != nil {
		return err
	}
	oidc["jwks"] = []map[string]interface{}{
		{
			"key": keyPEM,
		},
	}
	hmac, _ := oidc["hmac_secret"].(string)
	if hmac == "" {
		sec, _ := generateRandomSecret(32)
		oidc["hmac_secret"] = sec
	}

	return writeConfigFile(raw, getACFromMap(raw))
}

func getACFromMap(raw map[string]interface{}) AccessControlConfig {
	ac := AccessControlConfig{DefaultPolicy: "deny"}
	if rawAC, ok := raw["access_control"]; ok {
		acBytes, _ := yaml.Marshal(rawAC)
		_ = yaml.Unmarshal(acBytes, &ac)
	}
	return ac
}

func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Group helpers from users database
func getGroupsList() ([]GroupInfo, error) {
	udb, err := readUsersFile()
	if err != nil {
		return nil, err
	}

	groupMembers := make(map[string][]string)
	for username, rec := range udb.Users {
		for _, g := range rec.Groups {
			g = strings.TrimSpace(g)
			if g != "" {
				groupMembers[g] = append(groupMembers[g], username)
			}
		}
	}

	names := make([]string, 0, len(groupMembers))
	for name := range groupMembers {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]GroupInfo, 0, len(names))
	for _, name := range names {
		members := groupMembers[name]
		sort.Strings(members)
		result = append(result, GroupInfo{
			Name:    name,
			Members: members,
			Count:   len(members),
		})
	}
	return result, nil
}

func renameGroupInUsers(oldName, newName string) error {
	udb, err := readUsersFile()
	if err != nil {
		return err
	}
	for u, rec := range udb.Users {
		modified := false
		for i, g := range rec.Groups {
			if g == oldName {
				rec.Groups[i] = newName
				modified = true
			}
		}
		if modified {
			udb.Users[u] = rec
		}
	}
	return writeUsersFile(udb)
}

func deleteGroupInUsers(groupName string) error {
	udb, err := readUsersFile()
	if err != nil {
		return err
	}
	for u, rec := range udb.Users {
		var filtered []string
		for _, g := range rec.Groups {
			if g != groupName {
				filtered = append(filtered, g)
			}
		}
		if len(filtered) != len(rec.Groups) {
			rec.Groups = filtered
			udb.Users[u] = rec
		}
	}
	return writeUsersFile(udb)
}
func addGroupToUsers(groupName string, usernames []string) error {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return fmt.Errorf("group name cannot be empty")
	}
	udb, err := readUsersFile()
	if err != nil {
		return err
	}

	// Add group to specified users
	for _, u := range usernames {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if rec, exists := udb.Users[u]; exists {
			alreadyIn := false
			for _, g := range rec.Groups {
				if g == groupName {
					alreadyIn = true
					break
				}
			}
			if !alreadyIn {
				rec.Groups = append(rec.Groups, groupName)
				udb.Users[u] = rec
			}
		}
	}
	return writeUsersFile(udb)
}

