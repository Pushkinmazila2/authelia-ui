package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

var (
	configPath            = getEnv("CONFIG_PATH", "/config/configuration.yml")
	usersPath             = getEnv("USERS_PATH", "/config/users_database.yml")
	notificationPath      = getEnv("NOTIFICATION_PATH", "/config/notification.txt")
	dbPath                = getEnv("DB_PATH", "/config/db.sqlite3")
	dockerSocket          = getEnv("DOCKER_SOCKET", "/var/run/docker.sock")
	autheliaContainerName = getEnv("AUTHELIA_CONTAINER_NAME", "authelia")
	guardURL              = getEnv("GUARD_URL", "")
	listenAddr            = getEnv("LISTEN_ADDR", ":8080")
	fileLock              sync.RWMutex
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

type UserRecord struct {
	Password    string   `yaml:"password"`
	DisplayName string   `yaml:"displayname"`
	Email       string   `yaml:"email"`
	Groups      []string `yaml:"groups"`
	Disabled    bool     `yaml:"disabled,omitempty"`
}

type UsersDatabase struct {
	Users map[string]UserRecord `yaml:"users"`
}

type AccessControlRule struct {
	Domain    interface{} `yaml:"domain,omitempty"`
	Domains   interface{} `yaml:"domains,omitempty"`
	Policy    string      `yaml:"policy"`
	Subject   interface{} `yaml:"subject,omitempty"`
	Networks  interface{} `yaml:"networks,omitempty"`
	Methods   interface{} `yaml:"methods,omitempty"`
	Resources interface{} `yaml:"resources,omitempty"`
}

type AccessControlConfig struct {
	DefaultPolicy string              `yaml:"default_policy"`
	Rules         []AccessControlRule `yaml:"rules"`
}

type AutheliaStatus struct {
	Running           bool
	ContainerName     string
	ContainerImage    string
	Uptime            string
	HostConfigPath    string
	ConfigFound       bool
	UsersDBFound      bool
	DBFound           bool
	DBSize            int64
	NotificationLines string
	JWTStrength       string
	EncKeyStrength    string
	TLSConfigured     bool
}

func readUsersFile() (UsersDatabase, error) {
	fileLock.RLock()
	defer fileLock.RUnlock()

	var udb UsersDatabase
	data, err := os.ReadFile(usersPath)
	if err != nil {
		if os.IsNotExist(err) {
			return UsersDatabase{Users: make(map[string]UserRecord)}, nil
		}
		return udb, err
	}
	err = yaml.Unmarshal(data, &udb)
	if udb.Users == nil {
		udb.Users = make(map[string]UserRecord)
	}
	return udb, err
}

func writeUsersFile(udb UsersDatabase) error {
	fileLock.Lock()
	defer fileLock.Unlock()

	data, err := yaml.Marshal(udb)
	if err != nil {
		return err
	}
	return os.WriteFile(usersPath, data, 0600)
}

func readConfigFile() (map[string]interface{}, AccessControlConfig, error) {
	fileLock.RLock()
	defer fileLock.RUnlock()

	raw := make(map[string]interface{})
	ac := AccessControlConfig{DefaultPolicy: "deny"}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return raw, ac, err
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return raw, ac, err
	}

	if rawAC, ok := raw["access_control"]; ok {
		acBytes, _ := yaml.Marshal(rawAC)
		_ = yaml.Unmarshal(acBytes, &ac)
	}
	return raw, ac, nil
}

func writeConfigFile(raw map[string]interface{}, ac AccessControlConfig) error {
	fileLock.Lock()
	defer fileLock.Unlock()

	raw["access_control"] = ac
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0600)
}

func hashArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const memory uint32 = 65536
	const iterations uint32 = 3
	const parallelism uint8 = 4
	const keyLen uint32 = 32

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism, b64Salt, b64Hash), nil
}

func evaluateSecretStrength(secret string) string {
	l := len(secret)
	switch {
	case l == 0:
		return "MISSING"
	case l < 32:
		return "WEAK (<32 chars)"
	case l < 64:
		return "MEDIUM (<64 chars)"
	default:
		return "STRONG (>=64 chars)"
	}
}
