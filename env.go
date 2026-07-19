package configs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/joho/godotenv"
	"github.com/natifdevelopment/go-types"
)

var (
	// Vault
	VAULT_ADDR            string
	VAULT_ENDPOINT        string
	VAULT_TOKEN           string
	VAULT_PATH            string
	VAULT_MOUNT           string
	VAULT_SECRET_PATH     string
	VAULT_AUTH_METHOD     string
	VAULT_ROLE_ID         string
	VAULT_SECRET_ID       string
	VAULT_FALLBACK_TO_ENV bool
	SECRET_PROVIDER       string

	// Common
	SERVICE_NAME          string
	SERVICE_HOST          string
	SERVICE_PORT          string
	SERVICE_GIN_MODE      string
	SERVICE_TZ            string
	ENVIRONMENT           string
	ENV_DEV               string
	ENV_STAGING           string
	ENV_PROD              string
	BASE_URL              string
	ENABLE_AUTO_MIGRATION bool

	// Postgre
	DATABASE_POSTGRESQL_HOST     string
	DATABASE_POSTGRESQL_PORT     int
	DATABASE_POSTGRESQL_USER     string
	DATABASE_POSTGRESQL_PASSWORD string
	DATABASE_POSTGRESQL_DB_NAME  string

	// Postgre Slave (read-only replica)
	DATABASE_POSTGRESQL_SLAVE_HOST     string
	DATABASE_POSTGRESQL_SLAVE_PORT     int
	DATABASE_POSTGRESQL_SLAVE_USER     string
	DATABASE_POSTGRESQL_SLAVE_PASSWORD string
	DATABASE_POSTGRESQL_SLAVE_DB_NAME  string

	// Redis
	REDIS_HOST     string
	REDIS_PORT     string
	REDIS_USERNAME string
	REDIS_PASSWORD string
	REDIS_DB       int

	// S3 Storage
	S3_REGION           string
	S3_ACCESS_KEY_ID    string
	S3_SECRET_KEY       string
	S3_TOKEN            string
	S3_BUCKET_NAME      string
	S3_ENDPOINT         string
	S3_USE_SSL          bool
	S3_FORCE_PATH_STYLE bool

	// SSO (Single Sign On)
	SSO_CLIENT_ID            string
	SSO_CLIENT_SECRET        string
	SSO_API_SERVER_URL       string
	SSO_API_TOKEN_URL        string
	SSO_API_USER_INFO_URL    string
	SSO_API_VALIDATE_JWT_URL string
	SSO_REDIRECT_URL         string
	SSO_AUTHORIZE_URL        string

	// Cookie
	COOKIE_MAX_AGE   int
	COOKIE_PATH      string
	COOKIE_DOMAIN    string
	COOKIE_SECURE    bool
	COOKIE_HTTP_ONLY bool
	COOKIE_PREFIX    string

	// JWT
	JWT_SECRET_KEY string

	// CRYPTO
	CRYPTO_ENCRYPTION_KEY  string
	PAYLOAD_ENCRYPTION_KEY string
	CRYPTO_PASSWORD        string

	// Auto tester
	TESTER_EMAIL string

	// Super Admin Account
	SUPER_ADMIN_EMAIL string

	// FE
	FE_APP_NAME string
	FE_HOST     string
	FE_URL      string

	// PAGINATION
	PAGINATION_LIMIT           int
	ErrPaginationLimitExceeded = "Limit melebihi batas maksimum paginasi (%d)."

	// SQL PATTERNS
	SQLPatternLikeLower          = "LOWER(%s) LIKE LOWER('%%%s%%')"
	SQLPatternWhere              = " WHERE %s"
	SQLPatternAndKepemilikanCode = " AND kepemilikan_code = ?"
	SQLPatternAndPeriodeBetween  = " AND periode BETWEEN ? AND ?"
	SQLPatternAndRegionId        = " AND region_id = ?"
	SQLPatternAndPembangkitE     = " AND pembangkit_e = (SELECT name FROM t_organization WHERE id = ?)"
	SQLPatternAndPemasokA        = " AND pemasok_a = (SELECT name FROM t_organization WHERE id = ?)"
	SQLPatternAndWithParens      = " AND (%s)"

	APP_NAME       string = "BBO"
	VERSION_PREFIX string = "PLN"

	// RATE LIMITER
	RATE_LIMITER_ALERT_EMAIL string

	// GATEWAY
	TRUST_GATEWAY         bool
	GATEWAY_SHARED_SECRET string

	// LLM (used by S3 OCR, defaults to empty)
	LLM_API_URL       string
	LLM_API_TOKEN     string
	LLM_DEFAULT_MODEL string

	// UPLOAD
	UPLOAD_MAX_SIZE_MB int64
)

const (
	envVarPrefix = "environment variable "
)

var DefaultBaseURL string

func SetDefaultBaseURL(url string) {
	DefaultBaseURL = url
}

func GetEnv[T any](key string, defaultValue ...T) T {
	env := os.Getenv(key)
	if env == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		panic(envVarPrefix + key + " is not set")
	}

	var result any

	switch any(*new(T)).(type) {
	case string:
		result = env
	case int:
		v, err := strconv.Atoi(env)
		if err != nil {
			panic("failed to convert env to int: " + err.Error())
		}
		result = v
	case int64:
		v, err := strconv.ParseInt(env, 10, 64)
		if err != nil {
			panic("failed to convert env to int64: " + err.Error())
		}
		result = v
	case bool:
		v, err := strconv.ParseBool(env)
		if err != nil {
			panic("failed to convert env to bool: " + err.Error())
		}
		result = v
	default:
		panic("unsupported type for GetEnv")
	}

	return result.(T)
}

func SetupVault() error {
	fmt.Printf("[Vault] Starting Vault connection setup...\n")
	fmt.Printf("[Vault] Vault Address: %s\n", VAULT_ADDR)
	fmt.Printf("[Vault] Auth Method: %s\n", VAULT_AUTH_METHOD)
	fmt.Printf("[Vault] Secret Path: %s\n", VAULT_SECRET_PATH)
	fmt.Printf("[Vault] Mount: %s\n", VAULT_MOUNT)

	ctx := context.Background()

	fmt.Printf("[Vault] Creating Vault client...\n")
	client, err := vault.New(
		vault.WithAddress(VAULT_ADDR),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}
	fmt.Printf("[Vault] Vault client created successfully\n")

	if err := authenticateVaultClient(ctx, client); err != nil {
		return err
	}

	secretPrefix := strings.TrimSuffix(VAULT_SECRET_PATH, "/")
	if secretPrefix != "" {
		secretPrefix = secretPrefix + "/"
	}
	fmt.Printf("[Vault] Secret path prefix: %s\n", secretPrefix)

	fmt.Printf("[Vault] Reading secrets from Vault...\n")
	fmt.Printf("[Vault]   - Attempting to read flat secret structure: %s\n", secretPrefix)
	sAll, err := client.Secrets.KvV2Read(ctx, strings.TrimSuffix(secretPrefix, "/"), vault.WithMountPath(VAULT_MOUNT))
	if err != nil {
		return readAndApplyHierarchicalSecrets(ctx, client, secretPrefix)
	}

	fmt.Printf("[Vault]   - Flat secret structure found, parsing keys...\n")
	fmt.Printf("[Vault] All secrets read successfully, applying configuration...\n")
	setConfigFromFlatVault(sAll)
	fmt.Printf("[Vault] Vault configuration applied successfully\n")
	return nil
}

func authenticateVaultClient(ctx context.Context, client *vault.Client) error {
	if VAULT_AUTH_METHOD == "APPROLE" {
		return authenticateAppRole(ctx, client)
	}
	return authenticateToken(client)
}

func authenticateAppRole(ctx context.Context, client *vault.Client) error {
	fmt.Printf("[Vault] Using AppRole authentication...\n")
	if VAULT_ROLE_ID == "" || VAULT_SECRET_ID == "" {
		return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID are required for AppRole authentication")
	}
	fmt.Printf("[Vault] Attempting AppRole login...\n")

	resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   VAULT_ROLE_ID,
		SecretId: VAULT_SECRET_ID,
	})
	if err != nil {
		return fmt.Errorf("failed to login with AppRole: %w", err)
	}
	fmt.Printf("[Vault] AppRole login successful\n")

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		return fmt.Errorf("failed to set vault token: %w", err)
	}
	fmt.Printf("[Vault] Vault token set successfully\n")
	return nil
}

func authenticateToken(client *vault.Client) error {
	fmt.Printf("[Vault] Using Token authentication...\n")
	if VAULT_TOKEN == "" {
		return fmt.Errorf("VAULT_TOKEN is required for token authentication")
	}
	if err := client.SetToken(VAULT_TOKEN); err != nil {
		return fmt.Errorf("failed to set vault token: %w", err)
	}
	fmt.Printf("[Vault] Vault token set successfully\n")
	return nil
}

func readAndApplyHierarchicalSecrets(ctx context.Context, client *vault.Client, prefix string) error {
	fmt.Printf("[Vault]   - Flat structure failed, trying hierarchical structure...\n")

	paths := []string{"main", "database", "s3", "secret", "sso"}
	results := make(map[string]*vault.Response[schema.KvV2ReadResponse])

	for _, p := range paths {
		fmt.Printf("[Vault]   - Reading %s secret...\n", p)
		resp, err := client.Secrets.KvV2Read(ctx, prefix+p, vault.WithMountPath(VAULT_MOUNT))
		if err != nil {
			return fmt.Errorf("failed to read %s secret: %w", p, err)
		}
		fmt.Printf("[Vault]   - %s secret: OK\n", p)
		results[p] = resp
	}

	fmt.Printf("[Vault] All secrets read successfully, applying configuration...\n")
	setConfigFromVault(results["main"], results["database"], results["s3"], results["secret"], results["sso"])
	fmt.Printf("[Vault] Vault configuration applied successfully\n")
	return nil
}

func SetupEnvironment() {
	godotenv.Load(".env")

	loadCommonConfig()
	validateSecretProvider()

	if SECRET_PROVIDER == "VAULT" {
		setupVaultConfig()
		handleVaultConnection()
	} else {
		setConfigFromEnv()
	}
}

func loadCommonConfig() {
	ENV_DEV = "development"
	ENV_STAGING = "staging"
	ENV_PROD = "production"

	SERVICE_TZ = GetEnv("SERVICE_TZ", "Asia/Jakarta")
	SERVICE_NAME = GetEnv[string]("SERVICE_NAME")
	SERVICE_HOST = GetEnv[string]("SERVICE_HOST")
	SERVICE_PORT = GetEnv[string]("SERVICE_PORT")
	ENVIRONMENT = GetEnv("ENVIRONMENT", "development")
}

func validateSecretProvider() {
	SECRET_PROVIDER = GetEnv("SECRET_PROVIDER", "ENV")
	if SECRET_PROVIDER == "" {
		panic("SECRET_PROVIDER are not set on .env")
	}
	if SECRET_PROVIDER != "VAULT" && SECRET_PROVIDER != "ENV" {
		panic("SECRET_PROVIDER vault must set to VAULT or ENV")
	}
}

func setupVaultConfig() {
	VAULT_ADDR = GetEnv("VAULT_ADDR", "")
	VAULT_ENDPOINT = GetEnv("VAULT_ENDPOINT", "")
	if VAULT_ADDR == "" && VAULT_ENDPOINT != "" {
		VAULT_ADDR = VAULT_ENDPOINT
	}

	VAULT_MOUNT = GetEnv("VAULT_MOUNT", "")
	VAULT_SECRET_PATH = strings.TrimSuffix(GetEnv("VAULT_SECRET_PATH", ""), "/")
	VAULT_PATH = GetEnv("VAULT_PATH", "")

	parseVaultPath()

	if VAULT_MOUNT == "" {
		VAULT_MOUNT = "secret"
	}

	VAULT_AUTH_METHOD = GetEnv("VAULT_AUTH_METHOD", "TOKEN")
	VAULT_FALLBACK_TO_ENV = GetEnv("VAULT_FALLBACK_TO_ENV", false)

	if VAULT_ADDR == "" {
		panic("VAULT_ADDR (or VAULT_ENDPOINT) is not set on .env")
	}

	if VAULT_AUTH_METHOD != "TOKEN" && VAULT_AUTH_METHOD != "APPROLE" {
		panic("VAULT_AUTH_METHOD must be TOKEN or APPROLE")
	}

	setupVaultAuth()
}

func parseVaultPath() {
	if VAULT_MOUNT == "" && VAULT_PATH != "" {
		if idx := strings.Index(VAULT_PATH, "/data/"); idx != -1 {
			VAULT_MOUNT = VAULT_PATH[:idx]
			VAULT_SECRET_PATH = strings.TrimPrefix(VAULT_PATH[idx+len("/data/"):], "/")
		} else {
			VAULT_MOUNT = VAULT_PATH
		}
	}
}

func setupVaultAuth() {
	if VAULT_AUTH_METHOD == "APPROLE" {
		VAULT_ROLE_ID = GetEnv("VAULT_ROLE_ID", "")
		VAULT_SECRET_ID = GetEnv("VAULT_SECRET_ID", "")
	} else {
		VAULT_TOKEN = GetEnv("VAULT_TOKEN", "")
	}
}

func handleVaultConnection() {
	err := SetupVault()
	if err != nil {
		if VAULT_FALLBACK_TO_ENV {
			fmt.Printf("Warning: Vault connection failed (%v), falling back to .env\n", err)
			setConfigFromEnv()
		} else {
			panic(fmt.Sprintf("Vault connection failed: %v", err))
		}
	}
}

func setConfigFromVault(
	sMain *vault.Response[schema.KvV2ReadResponse],
	sDatabase *vault.Response[schema.KvV2ReadResponse],
	sS3 *vault.Response[schema.KvV2ReadResponse],
	sSecret *vault.Response[schema.KvV2ReadResponse],
	sSso *vault.Response[schema.KvV2ReadResponse],
) {
	BASE_URL = GetVaultItem(sMain, "BASE_URL", DefaultBaseURL)

	TESTER_EMAIL = GetVaultItem(sMain, "TESTER_EMAIL", "")
	SUPER_ADMIN_EMAIL = GetVaultItem(sMain, "SUPER_ADMIN_EMAIL", "")
	RATE_LIMITER_ALERT_EMAIL = GetVaultItem(sMain, "RATE_LIMITER_ALERT_EMAIL", "")

	FE_APP_NAME = GetVaultItem[string](sMain, "FE_APP_NAME")
	FE_HOST = GetVaultItem[string](sMain, "FE_HOST")
	FE_URL = GetVaultItem[string](sMain, "FE_URL")

	PAGINATION_LIMIT = GetVaultItem(sMain, "PAGINATION_LIMIT", 250)

	// POSTGRE
	DATABASE_POSTGRESQL_HOST = GetVaultItem[string](sDatabase, "DATABASE_POSTGRESQL_HOST")
	DATABASE_POSTGRESQL_PORT = GetVaultItem[int](sDatabase, "DATABASE_POSTGRESQL_PORT")
	DATABASE_POSTGRESQL_USER = GetVaultItem[string](sDatabase, "DATABASE_POSTGRESQL_USER")
	DATABASE_POSTGRESQL_PASSWORD = GetVaultItem[string](sSecret, "DATABASE_POSTGRESQL_PASSWORD")
	DATABASE_POSTGRESQL_DB_NAME = GetVaultItem[string](sDatabase, "DATABASE_POSTGRESQL_DB_NAME")
	ENABLE_AUTO_MIGRATION = GetVaultItem(sDatabase, "ENABLE_AUTO_MIGRATION", true)

	// POSTGRE SLAVE
	DATABASE_POSTGRESQL_SLAVE_HOST = GetVaultItem(sDatabase, "DATABASE_POSTGRESQL_SLAVE_HOST", "")
	DATABASE_POSTGRESQL_SLAVE_PORT = GetVaultItem(sDatabase, "DATABASE_POSTGRESQL_SLAVE_PORT", 0)
	DATABASE_POSTGRESQL_SLAVE_USER = GetVaultItem(sDatabase, "DATABASE_POSTGRESQL_SLAVE_USER", "")
	DATABASE_POSTGRESQL_SLAVE_PASSWORD = GetVaultItem(sSecret, "DATABASE_POSTGRESQL_SLAVE_PASSWORD", "")
	DATABASE_POSTGRESQL_SLAVE_DB_NAME = GetVaultItem(sDatabase, "DATABASE_POSTGRESQL_SLAVE_DB_NAME", "")

	// REDIS
	REDIS_HOST = GetVaultItem[string](sDatabase, "REDIS_HOST")
	REDIS_PORT = GetVaultItem[string](sDatabase, "REDIS_PORT")
	REDIS_USERNAME = GetVaultItem(sDatabase, "REDIS_USERNAME", "")
	REDIS_PASSWORD = GetVaultItem(sSecret, "REDIS_PASSWORD", "")
	REDIS_DB = GetVaultItem(sDatabase, "REDIS_DB", 0)

	// S3 STORAGE
	S3_REGION = GetVaultItem(sS3, "S3_REGION", "")
	S3_ACCESS_KEY_ID = GetVaultItem[string](sSecret, "S3_ACCESS_KEY_ID")
	S3_SECRET_KEY = GetVaultItem[string](sSecret, "S3_SECRET_KEY")
	S3_TOKEN = GetVaultItem(sSecret, "S3_TOKEN", "")
	S3_BUCKET_NAME = GetVaultItem[string](sS3, "S3_BUCKET_NAME")
	S3_ENDPOINT = GetVaultItem[string](sS3, "S3_ENDPOINT")
	S3_USE_SSL = GetVaultItem(sS3, "S3_USE_SSL", true)
	S3_FORCE_PATH_STYLE = GetVaultItem(sS3, "S3_FORCE_PATH_STYLE", true)

	// SSO (Single Sign On)
	SSO_CLIENT_ID = GetVaultItem[string](sSecret, "SSO_CLIENT_ID")
	SSO_CLIENT_SECRET = GetVaultItem[string](sSecret, "SSO_CLIENT_SECRET")
	SSO_API_SERVER_URL = GetVaultItem[string](sSso, "SSO_API_SERVER_URL")
	SSO_API_TOKEN_URL = GetVaultItem[string](sSso, "SSO_API_TOKEN_URL")
	SSO_API_USER_INFO_URL = GetVaultItem[string](sSso, "SSO_API_USER_INFO_URL")
	SSO_API_VALIDATE_JWT_URL = GetVaultItem[string](sSso, "SSO_API_VALIDATE_JWT_URL")
	SSO_REDIRECT_URL = GetVaultItem[string](sSso, "SSO_REDIRECT_URL")
	SSO_AUTHORIZE_URL = GetVaultItem(sSso, "SSO_AUTHORIZE_URL", "")

	// COOKIE
	COOKIE_MAX_AGE = GetVaultItem(sMain, "COOKIE_MAX_AGE", 3600)
	COOKIE_PATH = GetVaultItem(sMain, "COOKIE_PATH", "/")
	COOKIE_DOMAIN = GetVaultItem(sMain, "COOKIE_DOMAIN", "localhost")
	COOKIE_SECURE = GetVaultItem(sMain, "COOKIE_SECURE", true)
	COOKIE_HTTP_ONLY = GetVaultItem(sMain, "COOKIE_HTTP_ONLY", true)
	COOKIE_PREFIX = GetVaultItem(sMain, "COOKIE_PREFIX", "")

	// JWT
	JWT_SECRET_KEY = GetVaultItem[string](sSecret, "JWT_SECRET_KEY")

	// CRYPTO
	CRYPTO_ENCRYPTION_KEY = GetVaultItem[string](sSecret, "CRYPTO_ENCRYPTION_KEY")
	PAYLOAD_ENCRYPTION_KEY = GetVaultItem[string](sSecret, "PAYLOAD_ENCRYPTION_KEY")
	CRYPTO_PASSWORD = GetVaultItem(sSecret, "CRYPTO_PASSWORD", "")

	types.SetEncryptionKey(CRYPTO_ENCRYPTION_KEY)

	// GATEWAY
	TRUST_GATEWAY = GetVaultItem(sMain, "TRUST_GATEWAY", false)
	GATEWAY_SHARED_SECRET = GetVaultItem(sMain, "GATEWAY_SHARED_SECRET", "")

	// LLM
	LLM_API_URL = GetVaultItem(sMain, "LLM_API_URL", "")
	LLM_API_TOKEN = GetVaultItem(sMain, "LLM_API_TOKEN", "")
	LLM_DEFAULT_MODEL = GetVaultItem(sMain, "LLM_DEFAULT_MODEL", "")

	// UPLOAD
	UPLOAD_MAX_SIZE_MB = GetVaultItem(sMain, "UPLOAD_MAX_SIZE_MB", int64(10))
}

func setConfigFromFlatVault(sAll *vault.Response[schema.KvV2ReadResponse]) {
	BASE_URL = GetVaultItem(sAll, "BASE_URL", DefaultBaseURL)

	TESTER_EMAIL = GetVaultItem(sAll, "TESTER_EMAIL", "")
	SUPER_ADMIN_EMAIL = GetVaultItem(sAll, "SUPER_ADMIN_EMAIL", "")
	RATE_LIMITER_ALERT_EMAIL = GetVaultItem(sAll, "RATE_LIMITER_ALERT_EMAIL", "")

	FE_APP_NAME = GetVaultItem[string](sAll, "FE_APP_NAME")
	FE_HOST = GetVaultItem[string](sAll, "FE_HOST")
	FE_URL = GetVaultItem[string](sAll, "FE_URL")

	PAGINATION_LIMIT = GetVaultItem(sAll, "PAGINATION_LIMIT", 250)

	// POSTGRE
	DATABASE_POSTGRESQL_HOST = GetVaultItem[string](sAll, "DATABASE_POSTGRESQL_HOST")
	DATABASE_POSTGRESQL_PORT = GetVaultItem[int](sAll, "DATABASE_POSTGRESQL_PORT")
	DATABASE_POSTGRESQL_USER = GetVaultItem[string](sAll, "DATABASE_POSTGRESQL_USER")
	DATABASE_POSTGRESQL_PASSWORD = GetVaultItem[string](sAll, "DATABASE_POSTGRESQL_PASSWORD")
	DATABASE_POSTGRESQL_DB_NAME = GetVaultItem[string](sAll, "DATABASE_POSTGRESQL_DB_NAME")
	ENABLE_AUTO_MIGRATION = GetVaultItem(sAll, "ENABLE_AUTO_MIGRATION", true)

	// POSTGRE SLAVE
	DATABASE_POSTGRESQL_SLAVE_HOST = GetVaultItem(sAll, "DATABASE_POSTGRESQL_SLAVE_HOST", "")
	DATABASE_POSTGRESQL_SLAVE_PORT = GetVaultItem(sAll, "DATABASE_POSTGRESQL_SLAVE_PORT", 0)
	DATABASE_POSTGRESQL_SLAVE_USER = GetVaultItem(sAll, "DATABASE_POSTGRESQL_SLAVE_USER", "")
	DATABASE_POSTGRESQL_SLAVE_PASSWORD = GetVaultItem(sAll, "DATABASE_POSTGRESQL_SLAVE_PASSWORD", "")
	DATABASE_POSTGRESQL_SLAVE_DB_NAME = GetVaultItem(sAll, "DATABASE_POSTGRESQL_SLAVE_DB_NAME", "")

	// REDIS
	REDIS_HOST = GetVaultItem[string](sAll, "REDIS_HOST")
	REDIS_PORT = GetVaultItem[string](sAll, "REDIS_PORT")
	REDIS_USERNAME = GetVaultItem(sAll, "REDIS_USERNAME", "")
	REDIS_PASSWORD = GetVaultItem(sAll, "REDIS_PASSWORD", "")
	REDIS_DB = GetVaultItem(sAll, "REDIS_DB", 0)

	// S3 STORAGE
	S3_REGION = GetVaultItem(sAll, "S3_REGION", "")
	S3_ACCESS_KEY_ID = GetVaultItem[string](sAll, "S3_ACCESS_KEY_ID")
	S3_SECRET_KEY = GetVaultItem[string](sAll, "S3_SECRET_KEY")
	S3_TOKEN = GetVaultItem(sAll, "S3_TOKEN", "")
	S3_BUCKET_NAME = GetVaultItem[string](sAll, "S3_BUCKET_NAME")
	S3_ENDPOINT = GetVaultItem[string](sAll, "S3_ENDPOINT")
	S3_USE_SSL = GetVaultItem(sAll, "S3_USE_SSL", true)
	S3_FORCE_PATH_STYLE = GetVaultItem(sAll, "S3_FORCE_PATH_STYLE", true)

	// SSO (Single Sign On)
	SSO_CLIENT_ID = GetVaultItem(sAll, "SSO_CLIENT_ID", "")
	SSO_CLIENT_SECRET = GetVaultItem(sAll, "SSO_CLIENT_SECRET", "")
	SSO_API_SERVER_URL = GetVaultItem(sAll, "SSO_API_SERVER_URL", "")
	SSO_API_TOKEN_URL = GetVaultItem(sAll, "SSO_API_TOKEN_URL", "")
	SSO_API_USER_INFO_URL = GetVaultItem(sAll, "SSO_API_USER_INFO_URL", "")
	SSO_API_VALIDATE_JWT_URL = GetVaultItem(sAll, "SSO_API_VALIDATE_JWT_URL", "")
	SSO_REDIRECT_URL = GetVaultItem(sAll, "SSO_REDIRECT_URL", "")
	SSO_AUTHORIZE_URL = GetVaultItem(sAll, "SSO_AUTHORIZE_URL", "")

	// COOKIE
	COOKIE_MAX_AGE = GetVaultItem(sAll, "COOKIE_MAX_AGE", 3600)
	COOKIE_PATH = GetVaultItem(sAll, "COOKIE_PATH", "/")
	COOKIE_DOMAIN = GetVaultItem(sAll, "COOKIE_DOMAIN", "localhost")
	COOKIE_SECURE = GetVaultItem(sAll, "COOKIE_SECURE", true)
	COOKIE_HTTP_ONLY = GetVaultItem(sAll, "COOKIE_HTTP_ONLY", true)
	COOKIE_PREFIX = GetVaultItem(sAll, "COOKIE_PREFIX", "")

	// JWT
	JWT_SECRET_KEY = GetVaultItem[string](sAll, "JWT_SECRET_KEY")

	// CRYPTO
	CRYPTO_ENCRYPTION_KEY = GetVaultItem[string](sAll, "CRYPTO_ENCRYPTION_KEY")
	PAYLOAD_ENCRYPTION_KEY = GetVaultItem[string](sAll, "PAYLOAD_ENCRYPTION_KEY")
	CRYPTO_PASSWORD = GetVaultItem(sAll, "CRYPTO_PASSWORD", "")

	types.SetEncryptionKey(CRYPTO_ENCRYPTION_KEY)

	// GATEWAY
	TRUST_GATEWAY = GetVaultItem(sAll, "TRUST_GATEWAY", false)
	GATEWAY_SHARED_SECRET = GetVaultItem(sAll, "GATEWAY_SHARED_SECRET", "")

	// LLM
	LLM_API_URL = GetVaultItem(sAll, "LLM_API_URL", "")
	LLM_API_TOKEN = GetVaultItem(sAll, "LLM_API_TOKEN", "")
	LLM_DEFAULT_MODEL = GetVaultItem(sAll, "LLM_DEFAULT_MODEL", "")

	// UPLOAD
	UPLOAD_MAX_SIZE_MB = GetVaultItem(sAll, "UPLOAD_MAX_SIZE_MB", int64(10))
}

func setConfigFromEnv() {
	BASE_URL = GetEnv("BASE_URL", DefaultBaseURL)

	// POSTGRE
	DATABASE_POSTGRESQL_HOST = GetEnv[string]("DATABASE_POSTGRESQL_HOST")
	DATABASE_POSTGRESQL_PORT = GetEnv[int]("DATABASE_POSTGRESQL_PORT")
	DATABASE_POSTGRESQL_USER = GetEnv[string]("DATABASE_POSTGRESQL_USER")
	DATABASE_POSTGRESQL_PASSWORD = GetEnv[string]("DATABASE_POSTGRESQL_PASSWORD")
	DATABASE_POSTGRESQL_DB_NAME = GetEnv[string]("DATABASE_POSTGRESQL_DB_NAME")
	ENABLE_AUTO_MIGRATION = GetEnv("ENABLE_AUTO_MIGRATION", true)

	// POSTGRE SLAVE (optional, empty = no slave)
	DATABASE_POSTGRESQL_SLAVE_HOST = GetEnv("DATABASE_POSTGRESQL_SLAVE_HOST", "")
	DATABASE_POSTGRESQL_SLAVE_PORT = GetEnv("DATABASE_POSTGRESQL_SLAVE_PORT", 0)
	DATABASE_POSTGRESQL_SLAVE_USER = GetEnv("DATABASE_POSTGRESQL_SLAVE_USER", "")
	DATABASE_POSTGRESQL_SLAVE_PASSWORD = GetEnv("DATABASE_POSTGRESQL_SLAVE_PASSWORD", "")
	DATABASE_POSTGRESQL_SLAVE_DB_NAME = GetEnv("DATABASE_POSTGRESQL_SLAVE_DB_NAME", "")

	// REDIS
	REDIS_HOST = GetEnv[string]("REDIS_HOST")
	REDIS_PORT = GetEnv[string]("REDIS_PORT")
	REDIS_USERNAME = GetEnv("REDIS_USERNAME", "")
	REDIS_PASSWORD = GetEnv("REDIS_PASSWORD", "")
	REDIS_DB = GetEnv("REDIS_DB", 0)

	// S3 STORAGE
	S3_REGION = GetEnv("S3_REGION", "")
	S3_ACCESS_KEY_ID = GetEnv[string]("S3_ACCESS_KEY_ID")
	S3_SECRET_KEY = GetEnv[string]("S3_SECRET_KEY")
	S3_TOKEN = GetEnv("S3_TOKEN", "")
	S3_BUCKET_NAME = GetEnv[string]("S3_BUCKET_NAME")
	S3_ENDPOINT = GetEnv[string]("S3_ENDPOINT")
	S3_USE_SSL = GetEnv("S3_USE_SSL", true)
	S3_FORCE_PATH_STYLE = GetEnv("S3_FORCE_PATH_STYLE", true)

	// SSO (Single Sign On)
	SSO_CLIENT_ID = GetEnv[string]("SSO_CLIENT_ID")
	SSO_CLIENT_SECRET = GetEnv[string]("SSO_CLIENT_SECRET")
	SSO_API_SERVER_URL = GetEnv[string]("SSO_API_SERVER_URL")
	SSO_API_TOKEN_URL = GetEnv[string]("SSO_API_TOKEN_URL")
	SSO_API_USER_INFO_URL = GetEnv[string]("SSO_API_USER_INFO_URL")
	SSO_API_VALIDATE_JWT_URL = GetEnv[string]("SSO_API_VALIDATE_JWT_URL")
	SSO_REDIRECT_URL = GetEnv[string]("SSO_REDIRECT_URL")
	SSO_AUTHORIZE_URL = GetEnv("SSO_AUTHORIZE_URL", "")

	// COOKIE
	COOKIE_MAX_AGE = GetEnv("COOKIE_MAX_AGE", 3600)
	COOKIE_PATH = GetEnv("COOKIE_PATH", "/")
	COOKIE_DOMAIN = GetEnv("COOKIE_DOMAIN", "localhost")
	COOKIE_SECURE = GetEnv("COOKIE_SECURE", true)
	COOKIE_HTTP_ONLY = GetEnv("COOKIE_HTTP_ONLY", true)
	COOKIE_PREFIX = GetEnv("COOKIE_PREFIX", "")

	// JWT
	JWT_SECRET_KEY = GetEnv[string]("JWT_SECRET_KEY")

	// CRYPTO
	CRYPTO_ENCRYPTION_KEY = GetEnv[string]("CRYPTO_ENCRYPTION_KEY")
	PAYLOAD_ENCRYPTION_KEY = GetEnv[string]("PAYLOAD_ENCRYPTION_KEY")
	CRYPTO_PASSWORD = GetEnv("CRYPTO_PASSWORD", "")

	types.SetEncryptionKey(CRYPTO_ENCRYPTION_KEY)

	// AUTO TESTER LIST
	TESTER_EMAIL = GetEnv("TESTER_EMAIL", "")

	// SUPER ADMIN LIST
	SUPER_ADMIN_EMAIL = GetEnv("SUPER_ADMIN_EMAIL", "")

	// FE
	FE_APP_NAME = GetEnv[string]("FE_APP_NAME")
	FE_HOST = GetEnv[string]("FE_HOST")
	FE_URL = GetEnv[string]("FE_URL")

	// PAGINATION
	PAGINATION_LIMIT = GetEnv("PAGINATION_LIMIT", 250)

	RATE_LIMITER_ALERT_EMAIL = GetEnv("RATE_LIMITER_ALERT_EMAIL", "")

	// GATEWAY
	TRUST_GATEWAY = GetEnv("TRUST_GATEWAY", false)
	GATEWAY_SHARED_SECRET = GetEnv("GATEWAY_SHARED_SECRET", "")

	// LLM
	LLM_API_URL = GetEnv("LLM_API_URL", "")
	LLM_API_TOKEN = GetEnv("LLM_API_TOKEN", "")
	LLM_DEFAULT_MODEL = GetEnv("LLM_DEFAULT_MODEL", "")

	// UPLOAD
	UPLOAD_MAX_SIZE_MB = GetEnv[int64]("UPLOAD_MAX_SIZE_MB", 10)

	validateSecretKeys()
}

func validateSecretKeys() {
	const minJWTKeyLen = 32
	const minAESKeyLen = 16

	if len(JWT_SECRET_KEY) < minJWTKeyLen {
		panic(fmt.Sprintf("JWT_SECRET_KEY must be at least %d characters long", minJWTKeyLen))
	}
	if len(CRYPTO_ENCRYPTION_KEY) < minAESKeyLen {
		panic(fmt.Sprintf("CRYPTO_ENCRYPTION_KEY must be at least %d characters long", minAESKeyLen))
	}
	if PAYLOAD_ENCRYPTION_KEY != "" && len(PAYLOAD_ENCRYPTION_KEY) < minAESKeyLen {
		panic(fmt.Sprintf("PAYLOAD_ENCRYPTION_KEY must be at least %d characters long", minAESKeyLen))
	}
}

func GetVaultItem[T any](vaultData *vault.Response[schema.KvV2ReadResponse], key string, defaultValue ...T) T {
	env, ok := vaultData.Data.Data[key]
	if !ok || env == "" {
		return getVaultDefaultValue[T](key, defaultValue...)
	}

	if isNAValue(env) {
		return getVaultDefaultValue[T](key, defaultValue...)
	}

	return convertVaultValue[T](env, key)
}

func getVaultDefaultValue[T any](key string, defaultValue ...T) T {
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	panic(envVarPrefix + key + " is not set")
}

func isNAValue(env any) bool {
	str, ok := env.(string)
	return ok && (str == "n/a" || str == "N/A")
}

func convertVaultValue[T any](env any, key string) T {
	switch any(*new(T)).(type) {
	case string:
		return any(fmt.Sprintf("%v", env)).(T)
	case int:
		return any(convertToInt(env, key)).(T)
	case int64:
		return any(int64(convertToInt(env, key))).(T)
	case bool:
		return any(convertToBool(env, key)).(T)
	default:
		panic("unsupported type for GetEnv")
	}
}

func convertToInt(env any, key string) int {
	var v int64
	var err error

	if num, ok := env.(json.Number); ok {
		v, err = num.Int64()
	} else if str, ok := env.(string); ok {
		v, err = strconv.ParseInt(str, 10, 64)
	} else {
		panic("env " + key + " is not number or string")
	}

	if err != nil {
		panic("failed get env item " + key + " with error: " + err.Error())
	}

	return int(v)
}

func convertToBool(env any, key string) bool {
	if v, ok := env.(bool); ok {
		return v
	}

	str, ok := env.(string)
	if !ok {
		panic("env " + key + " is not boolean")
	}

	v, err := strconv.ParseBool(str)
	if err != nil {
		panic("env " + key + " is not boolean")
	}

	return v
}
