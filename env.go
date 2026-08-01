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
	VAULT_ADDR              string
	VAULT_ENDPOINT          string
	VAULT_TOKEN             string
	VAULT_PATH              string
	VAULT_MOUNT             string
	VAULT_SECRET_PATH       string
	VAULT_SECRET_PATHS      []string // multi-path support (comma-separated), takes precedence over VAULT_SECRET_PATH
	VAULT_SHARED_SUBPATHS   []string // sub-paths to read from shared paths (comma-separated), default: all
	VAULT_AUTH_METHOD       string
	VAULT_ROLE_ID           string // AppRole for service-specific path
	VAULT_SECRET_ID         string // AppRole for service-specific path
	VAULT_SHARED_ROLE_ID    string // AppRole for shared paths (optional, falls back to VAULT_ROLE_ID)
	VAULT_SHARED_SECRET_ID  string // AppRole for shared paths (optional, falls back to VAULT_SECRET_ID)
	VAULT_FALLBACK_TO_ENV   bool
	SECRET_PROVIDER         string

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

	// WEBSOCKET
	WS_READ_BUFFER_SIZE  int
	WS_WRITE_BUFFER_SIZE int

	// KAFKA
	KAFKA_BROKER            string
	KAFKA_BROKERS           string
	KAFKA_BROKER_ADDRESSES  string
	KAFKA_CLIENT_ID         string
	KAFKA_GROUP             string
	KAFKA_SASL_USER         string
	KAFKA_SASL_PASSWORD     string
	KAFKA_SASL_MECHANISM    string
	KAFKA_TLS_ENABLE        bool
	KAFKA_TLS_SKIP_VERIFY   bool

	// SERVICE-SPECIFIC (migrated from per-service configs/env.go)
	SERVICE_VERSION string
	AUTO_MIGRATION  bool

	// SCHEDULER
	DATA_CONNECTOR_CRON_EXP string
	JISDOR_CRON_EXP         string
	SENTRAL_CRON_EXP        string
	KURS_TENGAH_CRON_EXP    string
	ASSET_CRON_EXP          string

	// INTEGRATION
	AMS_TOKEN          string
	BI_KURS_TENGAH_URL string
	BI_JISDOR_URL      string
	SAP_BASE_URL       string
	SAP_API_KEY        string
	SAP_API_USER       string
	SAP_API_PASSWORD   string

	// CLAMAV
	CLAMAV_ENABLED bool
	CLAMAV_HOST    string
	CLAMAV_PORT    string

	// LLM
	LLM_ENDPOINT string
	LLM_EMAIL    string
	LLM_PASSWORD string

	// MAIL
	MAIL_HOST         string
	MAIL_PORT         int
	MAIL_USERNAME     string
	MAIL_PASSWORD     string
	MAIL_FROM_ADDRESS string
	MAIL_FROM_NAME    string

	// HELPDESK
	HELPDESK_EMAIL    string
	HELPDESK_PHONE    string
	HELPDESK_WHATSAPP string

	// SECURITY
	SECURITY_ISSUE_EMAIL string

	// SENTRY
	SENTRY_DSN         string
	SENTRY_SAMPLE_RATE float64

	// OTEL
	OTEL_TRACES_ENABLED           bool
	OTEL_TRACES_EXPORTER          string
	OTEL_EXPORTER_OTLP_ENDPOINT   string
	OTEL_EXPORTER_ZIPKIN_ENDPOINT string
	OTEL_TRACES_SAMPLE_RATE       float64

	// RECAPTCHA
	RECAPTCHA_SECRET_KEY string

	// WEBAUTHN
	WEBAUTHN_RP_ID      string
	WEBAUTHN_RP_NAME    string
	WEBAUTHN_RP_ORIGINS string

	// CORS
	CORS_ALLOW_ORIGINS string
)

const (
	envVarPrefix = "environment variable "
)

// LoadEnv is an alias for SetupEnvironment retained for backward compatibility
func LoadEnv() {
	SetupEnvironment()
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
	case float64:
		v, err := strconv.ParseFloat(env, 64)
		if err != nil {
			panic("failed to convert env to float64: " + err.Error())
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
	fmt.Printf("[Vault] Mount: %s\n", VAULT_MOUNT)

	// Multi-path mode: read from multiple paths and merge
	if len(VAULT_SECRET_PATHS) > 0 {
		fmt.Printf("[Vault] Multi-path mode: %d paths\n", len(VAULT_SECRET_PATHS))
		for i, p := range VAULT_SECRET_PATHS {
			fmt.Printf("[Vault]   Path %d: %s\n", i+1, p)
		}
		return setupVaultMultiPath()
	}

	// Single-path mode (backward compatible)
	fmt.Printf("[Vault] Secret Path: %s\n", VAULT_SECRET_PATH)
	return setupVaultSinglePath()
}

func setupVaultSinglePath() error {
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

// setupVaultMultiPath reads secrets from multiple Vault paths and merges them.
// Later paths override earlier ones (e.g., service-specific overrides shared).
// Each path is tried as flat first, then hierarchical sub-paths.
//
// Hierarchical sub-paths (for shared paths like development/bbo/shared):
//   main, database_postgre, redis, s3, sso, mail, llm
//
// Passwords live in their respective sub-path (e.g., DB password in database_postgre,
// Redis password in redis, S3 keys in s3, SSO secret in sso, Mail password in mail,
// LLM token in llm). JWT/CRYPTO/GATEWAY_SHARED_SECRET/AMS/SAP/RECAPTCHA live in main.
//
// Service-specific paths (e.g., development/bbo/bbo-billing-api) are typically flat.
// CLAMAV_* lives in shared/main (read by all, used only by services that need it).
// WEBAUTHN falls back to FE_* values if empty (see webauthn.go), so no separate sub-path needed.
func setupVaultMultiPath() error {
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

	// merged accumulates all secrets from all paths; later paths override earlier
	merged := make(map[string]any)

	// Hierarchical sub-paths for shared infrastructure secrets.
	// If VAULT_SHARED_SUBPATHS is set, use only those (least-privilege per service).
	// Otherwise default to all sub-paths (backward compatible).
	defaultSubPaths := []string{"main", "database_postgre", "redis", "s3", "sso", "mail", "llm"}
	hierarchicalSubPaths := defaultSubPaths
	if len(VAULT_SHARED_SUBPATHS) > 0 {
		hierarchicalSubPaths = VAULT_SHARED_SUBPATHS
		fmt.Printf("[Vault] Using selective sub-paths: %v\n", hierarchicalSubPaths)
	}

	// Detect if shared AppRole is different from service AppRole
	useDualAppRole := VAULT_AUTH_METHOD == "APPROLE" &&
		(VAULT_SHARED_ROLE_ID != VAULT_ROLE_ID || VAULT_SHARED_SECRET_ID != VAULT_SECRET_ID)

	// Create shared client if dual AppRole
	var sharedClient *vault.Client
	if useDualAppRole {
		fmt.Printf("[Vault] Using dual AppRole: shared + service-specific\n")
		sharedClient, err = vault.New(
			vault.WithAddress(VAULT_ADDR),
			vault.WithRequestTimeout(30*time.Second),
		)
		if err != nil {
			return fmt.Errorf("failed to create shared vault client: %w", err)
		}
		if err := authenticateSharedAppRole(ctx, sharedClient); err != nil {
			return err
		}
	}

	// Authenticate service-specific client
	if err := authenticateVaultClient(ctx, client); err != nil {
		return err
	}

	// Determine which paths are "shared" (use shared AppRole) vs "service-specific" (use service AppRole)
	// Heuristic: path containing "/shared" uses shared AppRole, others use service AppRole
	for _, path := range VAULT_SECRET_PATHS {
		fmt.Printf("[Vault] Reading path: %s\n", path)

		// Select client: shared paths use sharedClient (if dual), others use service client
		activeClient := client
		if useDualAppRole && strings.Contains(path, "/shared") {
			activeClient = sharedClient
			fmt.Printf("[Vault]   - Using shared AppRole for this path\n")
		}

		// Try flat read first (service-specific paths are usually flat)
		sAll, err := activeClient.Secrets.KvV2Read(ctx, path, vault.WithMountPath(VAULT_MOUNT))
		if err == nil {
			fmt.Printf("[Vault]   - Flat structure found for: %s\n", path)
			mergeVaultData(merged, sAll.Data.Data)
			continue
		}

		// Try hierarchical sub-paths (shared paths use this structure)
		fmt.Printf("[Vault]   - Flat failed for %s, trying hierarchical...\n", path)
		anySuccess := false
		for _, sub := range hierarchicalSubPaths {
			fullPath := path + "/" + sub
			resp, err := activeClient.Secrets.KvV2Read(ctx, fullPath, vault.WithMountPath(VAULT_MOUNT))
			if err != nil {
				fmt.Printf("[Vault]   - %s/%s: not found (skipping)\n", path, sub)
				continue
			}
			fmt.Printf("[Vault]   - %s/%s: OK\n", path, sub)
			mergeVaultData(merged, resp.Data.Data)
			anySuccess = true
		}

		if !anySuccess {
			return fmt.Errorf("failed to read any secrets from path: %s (tried flat and hierarchical)", path)
		}
	}

	fmt.Printf("[Vault] All paths read successfully, merged %d keys\n", len(merged))
	fmt.Printf("[Vault] Applying merged configuration...\n")
	setConfigFromMergedVault(merged)
	fmt.Printf("[Vault] Vault configuration applied successfully\n")
	return nil
}

// authenticateSharedAppRole logs in with the shared AppRole credentials.
func authenticateSharedAppRole(ctx context.Context, client *vault.Client) error {
	fmt.Printf("[Vault] Using shared AppRole authentication...\n")
	if VAULT_SHARED_ROLE_ID == "" || VAULT_SHARED_SECRET_ID == "" {
		return fmt.Errorf("VAULT_SHARED_ROLE_ID and VAULT_SHARED_SECRET_ID are required for shared AppRole")
	}
	resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   VAULT_SHARED_ROLE_ID,
		SecretId: VAULT_SHARED_SECRET_ID,
	})
	if err != nil {
		return fmt.Errorf("failed to login with shared AppRole: %w", err)
	}
	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		return fmt.Errorf("failed to set shared vault token: %w", err)
	}
	fmt.Printf("[Vault] Shared AppRole login successful\n")
	return nil
}

// mergeVaultData merges src into dst. Keys in src override keys in dst.
func mergeVaultData(dst map[string]any, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
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

	// Multi-path support: VAULT_SECRET_PATHS (comma-separated) takes precedence over VAULT_SECRET_PATH
	// Example: "development/bbo/shared,development/bbo/bbo-shipment-cfr-api"
	// Later paths override earlier ones (service-specific overrides shared).
	multiPaths := GetEnv("VAULT_SECRET_PATHS", "")
	if multiPaths != "" {
		for _, p := range strings.Split(multiPaths, ",") {
			p = strings.TrimSpace(p)
			p = strings.TrimSuffix(p, "/")
			if p != "" {
				VAULT_SECRET_PATHS = append(VAULT_SECRET_PATHS, p)
			}
		}
	}

	// Selective sub-paths: VAULT_SHARED_SUBPATHS (comma-separated)
	// Lets each service declare which shared sub-paths it needs (least-privilege).
	// Example: "database_postgre,redis,secret,sso" (no kafka/s3 if not needed)
	// Default: all sub-paths are tried (backward compatible).
	sharedSubPaths := GetEnv("VAULT_SHARED_SUBPATHS", "")
	if sharedSubPaths != "" {
		for _, p := range strings.Split(sharedSubPaths, ",") {
			p = strings.TrimSpace(p)
			p = strings.TrimSuffix(p, "/")
			if p != "" {
				VAULT_SHARED_SUBPATHS = append(VAULT_SHARED_SUBPATHS, p)
			}
		}
	}

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
		// Shared AppRole (optional — falls back to service-specific if not set)
		VAULT_SHARED_ROLE_ID = GetEnv("VAULT_SHARED_ROLE_ID", VAULT_ROLE_ID)
		VAULT_SHARED_SECRET_ID = GetEnv("VAULT_SHARED_SECRET_ID", VAULT_SECRET_ID)
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
	ENVIRONMENT = GetVaultItem(sMain, "ENVIRONMENT", ENVIRONMENT)
	BASE_URL = GetVaultItem(sMain, "BASE_URL", "")

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
	COOKIE_DOMAIN = GetVaultItem(sMain, "COOKIE_DOMAIN", "")
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

	// MAIL
	MAIL_HOST = GetVaultItem(sMain, "MAIL_HOST", "")
	MAIL_PORT = GetVaultItem(sMain, "MAIL_PORT", 587)
	MAIL_USERNAME = GetVaultItem(sMain, "MAIL_USERNAME", "")
	MAIL_PASSWORD = GetVaultItem(sSecret, "MAIL_PASSWORD", "")
	MAIL_FROM_ADDRESS = GetVaultItem(sMain, "MAIL_FROM_ADDRESS", "")
	MAIL_FROM_NAME = GetVaultItem(sMain, "MAIL_FROM_NAME", "")

	// HELPDESK
	HELPDESK_EMAIL = GetVaultItem(sMain, "HELPDESK_EMAIL", "")
	HELPDESK_PHONE = GetVaultItem(sMain, "HELPDESK_PHONE", "")
	HELPDESK_WHATSAPP = GetVaultItem(sMain, "HELPDESK_WHATSAPP", "")

	// SECURITY
	SECURITY_ISSUE_EMAIL = GetVaultItem(sMain, "SECURITY_ISSUE_EMAIL", "")

	// CLAMAV
	CLAMAV_ENABLED = GetVaultItem(sMain, "CLAMAV_ENABLED", false)
	CLAMAV_HOST = GetVaultItem(sMain, "CLAMAV_HOST", "")
	CLAMAV_PORT = GetVaultItem(sMain, "CLAMAV_PORT", "")

	// LLM (legacy)
	LLM_ENDPOINT = GetVaultItem(sMain, "LLM_ENDPOINT", "")
	LLM_EMAIL = GetVaultItem(sMain, "LLM_EMAIL", "")
	LLM_PASSWORD = GetVaultItem(sSecret, "LLM_PASSWORD", "")

	// RECAPTCHA
	RECAPTCHA_SECRET_KEY = GetVaultItem(sSecret, "RECAPTCHA_SECRET_KEY", "")

	// WEBAUTHN
	WEBAUTHN_RP_ID = GetVaultItem(sMain, "WEBAUTHN_RP_ID", "")
	WEBAUTHN_RP_NAME = GetVaultItem(sMain, "WEBAUTHN_RP_NAME", "")
	WEBAUTHN_RP_ORIGINS = GetVaultItem(sMain, "WEBAUTHN_RP_ORIGINS", "")

	// CORS
	CORS_ALLOW_ORIGINS = GetVaultItem(sMain, "CORS_ALLOW_ORIGINS", "")

	// SENTRY
	SENTRY_DSN = GetVaultItem(sMain, "SENTRY_DSN", "")
	SENTRY_SAMPLE_RATE = GetVaultItem(sMain, "SENTRY_SAMPLE_RATE", 1.0)

	// OTEL
	OTEL_TRACES_ENABLED = GetVaultItem(sMain, "OTEL_TRACES_ENABLED", false)
	OTEL_TRACES_EXPORTER = GetVaultItem(sMain, "OTEL_TRACES_EXPORTER", "otlp")
	OTEL_EXPORTER_OTLP_ENDPOINT = GetVaultItem(sMain, "OTEL_EXPORTER_OTLP_ENDPOINT", "")
	OTEL_EXPORTER_ZIPKIN_ENDPOINT = GetVaultItem(sMain, "OTEL_EXPORTER_ZIPKIN_ENDPOINT", "")
	OTEL_TRACES_SAMPLE_RATE = GetVaultItem(sMain, "OTEL_TRACES_SAMPLE_RATE", 0.05)

	// SERVICE-SPECIFIC
	SERVICE_VERSION = GetVaultItem(sMain, "SERVICE_VERSION", "")
	AUTO_MIGRATION = GetVaultItem(sMain, "AUTO_MIGRATION", false)

	// SCHEDULER
	DATA_CONNECTOR_CRON_EXP = GetVaultItem(sMain, "DATA_CONNECTOR_CRON_EXP", "")
	JISDOR_CRON_EXP = GetVaultItem(sMain, "JISDOR_CRON_EXP", "")
	SENTRAL_CRON_EXP = GetVaultItem(sMain, "SENTRAL_CRON_EXP", "")
	KURS_TENGAH_CRON_EXP = GetVaultItem(sMain, "KURS_TENGAH_CRON_EXP", "")
	ASSET_CRON_EXP = GetVaultItem(sMain, "ASSET_CRON_EXP", "")

	// INTEGRATION
	AMS_TOKEN = GetVaultItem(sSecret, "AMS_TOKEN", "")
	BI_KURS_TENGAH_URL = GetVaultItem(sMain, "BI_KURS_TENGAH_URL", "")
	BI_JISDOR_URL = GetVaultItem(sMain, "BI_JISDOR_URL", "")
	SAP_BASE_URL = GetVaultItem(sMain, "SAP_BASE_URL", "")
	SAP_API_KEY = GetVaultItem(sSecret, "SAP_API_KEY", "")
	SAP_API_USER = GetVaultItem(sMain, "SAP_API_USER", "")
	SAP_API_PASSWORD = GetVaultItem(sSecret, "SAP_API_PASSWORD", "")

	// UPLOAD
	UPLOAD_MAX_SIZE_MB = GetVaultItem(sMain, "UPLOAD_MAX_SIZE_MB", int64(10))
	WS_READ_BUFFER_SIZE = GetVaultItem(sMain, "WS_READ_BUFFER_SIZE", 1024)
	WS_WRITE_BUFFER_SIZE = GetVaultItem(sMain, "WS_WRITE_BUFFER_SIZE", 1024)

	// KAFKA
	KAFKA_BROKER = GetVaultItem(sMain, "KAFKA_BROKER", "")
	KAFKA_BROKERS = GetVaultItem(sMain, "KAFKA_BROKERS", "")
	KAFKA_BROKER_ADDRESSES = GetVaultItem(sMain, "KAFKA_BROKER_ADDRESSES", "")
	KAFKA_CLIENT_ID = GetVaultItem(sMain, "KAFKA_CLIENT_ID", "")
	KAFKA_GROUP = GetVaultItem(sMain, "KAFKA_GROUP", "")
	KAFKA_SASL_USER = GetVaultItem(sSecret, "KAFKA_SASL_USER", "")
	KAFKA_SASL_PASSWORD = GetVaultItem(sSecret, "KAFKA_SASL_PASSWORD", "")
	KAFKA_SASL_MECHANISM = GetVaultItem(sMain, "KAFKA_SASL_MECHANISM", "SCRAM-SHA-512")
	KAFKA_TLS_ENABLE = GetVaultItem(sMain, "KAFKA_TLS_ENABLE", false)
	KAFKA_TLS_SKIP_VERIFY = GetVaultItem(sMain, "KAFKA_TLS_SKIP_VERIFY", false)
}

func setConfigFromFlatVault(sAll *vault.Response[schema.KvV2ReadResponse]) {
	ENVIRONMENT = GetVaultItem(sAll, "ENVIRONMENT", ENVIRONMENT)
	BASE_URL = GetVaultItem(sAll, "BASE_URL", "")

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
	COOKIE_DOMAIN = GetVaultItem(sAll, "COOKIE_DOMAIN", "")
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

	// MAIL
	MAIL_HOST = GetVaultItem(sAll, "MAIL_HOST", "")
	MAIL_PORT = GetVaultItem(sAll, "MAIL_PORT", 587)
	MAIL_USERNAME = GetVaultItem(sAll, "MAIL_USERNAME", "")
	MAIL_PASSWORD = GetVaultItem(sAll, "MAIL_PASSWORD", "")
	MAIL_FROM_ADDRESS = GetVaultItem(sAll, "MAIL_FROM_ADDRESS", "")
	MAIL_FROM_NAME = GetVaultItem(sAll, "MAIL_FROM_NAME", "")

	// HELPDESK
	HELPDESK_EMAIL = GetVaultItem(sAll, "HELPDESK_EMAIL", "")
	HELPDESK_PHONE = GetVaultItem(sAll, "HELPDESK_PHONE", "")
	HELPDESK_WHATSAPP = GetVaultItem(sAll, "HELPDESK_WHATSAPP", "")

	// SECURITY
	SECURITY_ISSUE_EMAIL = GetVaultItem(sAll, "SECURITY_ISSUE_EMAIL", "")

	// CLAMAV
	CLAMAV_ENABLED = GetVaultItem(sAll, "CLAMAV_ENABLED", false)
	CLAMAV_HOST = GetVaultItem(sAll, "CLAMAV_HOST", "")
	CLAMAV_PORT = GetVaultItem(sAll, "CLAMAV_PORT", "")

	// LLM (legacy)
	LLM_ENDPOINT = GetVaultItem(sAll, "LLM_ENDPOINT", "")
	LLM_EMAIL = GetVaultItem(sAll, "LLM_EMAIL", "")
	LLM_PASSWORD = GetVaultItem(sAll, "LLM_PASSWORD", "")

	// RECAPTCHA
	RECAPTCHA_SECRET_KEY = GetVaultItem(sAll, "RECAPTCHA_SECRET_KEY", "")

	// WEBAUTHN
	WEBAUTHN_RP_ID = GetVaultItem(sAll, "WEBAUTHN_RP_ID", "")
	WEBAUTHN_RP_NAME = GetVaultItem(sAll, "WEBAUTHN_RP_NAME", "")
	WEBAUTHN_RP_ORIGINS = GetVaultItem(sAll, "WEBAUTHN_RP_ORIGINS", "")

	// CORS
	CORS_ALLOW_ORIGINS = GetVaultItem(sAll, "CORS_ALLOW_ORIGINS", "")

	// SENTRY
	SENTRY_DSN = GetVaultItem(sAll, "SENTRY_DSN", "")
	SENTRY_SAMPLE_RATE = GetVaultItem(sAll, "SENTRY_SAMPLE_RATE", 1.0)

	// OTEL
	OTEL_TRACES_ENABLED = GetVaultItem(sAll, "OTEL_TRACES_ENABLED", false)
	OTEL_TRACES_EXPORTER = GetVaultItem(sAll, "OTEL_TRACES_EXPORTER", "otlp")
	OTEL_EXPORTER_OTLP_ENDPOINT = GetVaultItem(sAll, "OTEL_EXPORTER_OTLP_ENDPOINT", "")
	OTEL_EXPORTER_ZIPKIN_ENDPOINT = GetVaultItem(sAll, "OTEL_EXPORTER_ZIPKIN_ENDPOINT", "")
	OTEL_TRACES_SAMPLE_RATE = GetVaultItem(sAll, "OTEL_TRACES_SAMPLE_RATE", 0.05)

	// SERVICE-SPECIFIC
	SERVICE_VERSION = GetVaultItem(sAll, "SERVICE_VERSION", "")
	AUTO_MIGRATION = GetVaultItem(sAll, "AUTO_MIGRATION", false)

	// SCHEDULER
	DATA_CONNECTOR_CRON_EXP = GetVaultItem(sAll, "DATA_CONNECTOR_CRON_EXP", "")
	JISDOR_CRON_EXP = GetVaultItem(sAll, "JISDOR_CRON_EXP", "")
	SENTRAL_CRON_EXP = GetVaultItem(sAll, "SENTRAL_CRON_EXP", "")
	KURS_TENGAH_CRON_EXP = GetVaultItem(sAll, "KURS_TENGAH_CRON_EXP", "")
	ASSET_CRON_EXP = GetVaultItem(sAll, "ASSET_CRON_EXP", "")

	// INTEGRATION
	AMS_TOKEN = GetVaultItem(sAll, "AMS_TOKEN", "")
	BI_KURS_TENGAH_URL = GetVaultItem(sAll, "BI_KURS_TENGAH_URL", "")
	BI_JISDOR_URL = GetVaultItem(sAll, "BI_JISDOR_URL", "")
	SAP_BASE_URL = GetVaultItem(sAll, "SAP_BASE_URL", "")
	SAP_API_KEY = GetVaultItem(sAll, "SAP_API_KEY", "")
	SAP_API_USER = GetVaultItem(sAll, "SAP_API_USER", "")
	SAP_API_PASSWORD = GetVaultItem(sAll, "SAP_API_PASSWORD", "")

	// UPLOAD
	UPLOAD_MAX_SIZE_MB = GetVaultItem(sAll, "UPLOAD_MAX_SIZE_MB", int64(10))
	WS_READ_BUFFER_SIZE = GetVaultItem(sAll, "WS_READ_BUFFER_SIZE", 1024)
	WS_WRITE_BUFFER_SIZE = GetVaultItem(sAll, "WS_WRITE_BUFFER_SIZE", 1024)

	// KAFKA
	KAFKA_BROKER = GetVaultItem(sAll, "KAFKA_BROKER", "")
	KAFKA_BROKERS = GetVaultItem(sAll, "KAFKA_BROKERS", "")
	KAFKA_BROKER_ADDRESSES = GetVaultItem(sAll, "KAFKA_BROKER_ADDRESSES", "")
	KAFKA_CLIENT_ID = GetVaultItem(sAll, "KAFKA_CLIENT_ID", "")
	KAFKA_GROUP = GetVaultItem(sAll, "KAFKA_GROUP", "")
	KAFKA_SASL_USER = GetVaultItem(sAll, "KAFKA_SASL_USER", "")
	KAFKA_SASL_PASSWORD = GetVaultItem(sAll, "KAFKA_SASL_PASSWORD", "")
	KAFKA_SASL_MECHANISM = GetVaultItem(sAll, "KAFKA_SASL_MECHANISM", "SCRAM-SHA-512")
	KAFKA_TLS_ENABLE = GetVaultItem(sAll, "KAFKA_TLS_ENABLE", false)
	KAFKA_TLS_SKIP_VERIFY = GetVaultItem(sAll, "KAFKA_TLS_SKIP_VERIFY", false)
}

// setConfigFromMergedVault applies config from a merged map of secrets gathered
// from multiple Vault paths. It mirrors setConfigFromFlatVault but uses GetMergedItem.
func setConfigFromMergedVault(merged map[string]any) {
	ENVIRONMENT = GetMergedItem(merged, "ENVIRONMENT", ENVIRONMENT)
	BASE_URL = GetMergedItem(merged, "BASE_URL", "")

	TESTER_EMAIL = GetMergedItem(merged, "TESTER_EMAIL", "")
	SUPER_ADMIN_EMAIL = GetMergedItem(merged, "SUPER_ADMIN_EMAIL", "")
	RATE_LIMITER_ALERT_EMAIL = GetMergedItem(merged, "RATE_LIMITER_ALERT_EMAIL", "")

	FE_APP_NAME = GetMergedItem[string](merged, "FE_APP_NAME")
	FE_HOST = GetMergedItem[string](merged, "FE_HOST")
	FE_URL = GetMergedItem[string](merged, "FE_URL")

	PAGINATION_LIMIT = GetMergedItem(merged, "PAGINATION_LIMIT", 250)

	// POSTGRE
	DATABASE_POSTGRESQL_HOST = GetMergedItem[string](merged, "DATABASE_POSTGRESQL_HOST")
	DATABASE_POSTGRESQL_PORT = GetMergedItem[int](merged, "DATABASE_POSTGRESQL_PORT")
	DATABASE_POSTGRESQL_USER = GetMergedItem[string](merged, "DATABASE_POSTGRESQL_USER")
	DATABASE_POSTGRESQL_PASSWORD = GetMergedItem[string](merged, "DATABASE_POSTGRESQL_PASSWORD")
	DATABASE_POSTGRESQL_DB_NAME = GetMergedItem[string](merged, "DATABASE_POSTGRESQL_DB_NAME")
	ENABLE_AUTO_MIGRATION = GetMergedItem(merged, "ENABLE_AUTO_MIGRATION", true)

	// POSTGRE SLAVE
	DATABASE_POSTGRESQL_SLAVE_HOST = GetMergedItem(merged, "DATABASE_POSTGRESQL_SLAVE_HOST", "")
	DATABASE_POSTGRESQL_SLAVE_PORT = GetMergedItem(merged, "DATABASE_POSTGRESQL_SLAVE_PORT", 0)
	DATABASE_POSTGRESQL_SLAVE_USER = GetMergedItem(merged, "DATABASE_POSTGRESQL_SLAVE_USER", "")
	DATABASE_POSTGRESQL_SLAVE_PASSWORD = GetMergedItem(merged, "DATABASE_POSTGRESQL_SLAVE_PASSWORD", "")
	DATABASE_POSTGRESQL_SLAVE_DB_NAME = GetMergedItem(merged, "DATABASE_POSTGRESQL_SLAVE_DB_NAME", "")

	// REDIS
	REDIS_HOST = GetMergedItem[string](merged, "REDIS_HOST")
	REDIS_PORT = GetMergedItem[string](merged, "REDIS_PORT")
	REDIS_USERNAME = GetMergedItem(merged, "REDIS_USERNAME", "")
	REDIS_PASSWORD = GetMergedItem(merged, "REDIS_PASSWORD", "")
	REDIS_DB = GetMergedItem(merged, "REDIS_DB", 0)

	// S3 STORAGE
	S3_REGION = GetMergedItem(merged, "S3_REGION", "")
	S3_ACCESS_KEY_ID = GetMergedItem[string](merged, "S3_ACCESS_KEY_ID")
	S3_SECRET_KEY = GetMergedItem[string](merged, "S3_SECRET_KEY")
	S3_TOKEN = GetMergedItem(merged, "S3_TOKEN", "")
	S3_BUCKET_NAME = GetMergedItem[string](merged, "S3_BUCKET_NAME")
	S3_ENDPOINT = GetMergedItem[string](merged, "S3_ENDPOINT")
	S3_USE_SSL = GetMergedItem(merged, "S3_USE_SSL", true)
	S3_FORCE_PATH_STYLE = GetMergedItem(merged, "S3_FORCE_PATH_STYLE", true)

	// SSO (Single Sign On)
	SSO_CLIENT_ID = GetMergedItem(merged, "SSO_CLIENT_ID", "")
	SSO_CLIENT_SECRET = GetMergedItem(merged, "SSO_CLIENT_SECRET", "")
	SSO_API_SERVER_URL = GetMergedItem(merged, "SSO_API_SERVER_URL", "")
	SSO_API_TOKEN_URL = GetMergedItem(merged, "SSO_API_TOKEN_URL", "")
	SSO_API_USER_INFO_URL = GetMergedItem(merged, "SSO_API_USER_INFO_URL", "")
	SSO_API_VALIDATE_JWT_URL = GetMergedItem(merged, "SSO_API_VALIDATE_JWT_URL", "")
	SSO_REDIRECT_URL = GetMergedItem(merged, "SSO_REDIRECT_URL", "")
	SSO_AUTHORIZE_URL = GetMergedItem(merged, "SSO_AUTHORIZE_URL", "")

	// COOKIE
	COOKIE_MAX_AGE = GetMergedItem(merged, "COOKIE_MAX_AGE", 3600)
	COOKIE_PATH = GetMergedItem(merged, "COOKIE_PATH", "/")
	COOKIE_DOMAIN = GetMergedItem(merged, "COOKIE_DOMAIN", "")
	COOKIE_SECURE = GetMergedItem(merged, "COOKIE_SECURE", true)
	COOKIE_HTTP_ONLY = GetMergedItem(merged, "COOKIE_HTTP_ONLY", true)
	COOKIE_PREFIX = GetMergedItem(merged, "COOKIE_PREFIX", "")

	// JWT
	JWT_SECRET_KEY = GetMergedItem[string](merged, "JWT_SECRET_KEY")

	// CRYPTO
	CRYPTO_ENCRYPTION_KEY = GetMergedItem[string](merged, "CRYPTO_ENCRYPTION_KEY")
	PAYLOAD_ENCRYPTION_KEY = GetMergedItem[string](merged, "PAYLOAD_ENCRYPTION_KEY")
	CRYPTO_PASSWORD = GetMergedItem(merged, "CRYPTO_PASSWORD", "")

	types.SetEncryptionKey(CRYPTO_ENCRYPTION_KEY)

	// GATEWAY
	TRUST_GATEWAY = GetMergedItem(merged, "TRUST_GATEWAY", false)
	GATEWAY_SHARED_SECRET = GetMergedItem(merged, "GATEWAY_SHARED_SECRET", "")

	// LLM
	LLM_API_URL = GetMergedItem(merged, "LLM_API_URL", "")
	LLM_API_TOKEN = GetMergedItem(merged, "LLM_API_TOKEN", "")
	LLM_DEFAULT_MODEL = GetMergedItem(merged, "LLM_DEFAULT_MODEL", "")

	// MAIL
	MAIL_HOST = GetMergedItem(merged, "MAIL_HOST", "")
	MAIL_PORT = GetMergedItem(merged, "MAIL_PORT", 587)
	MAIL_USERNAME = GetMergedItem(merged, "MAIL_USERNAME", "")
	MAIL_PASSWORD = GetMergedItem(merged, "MAIL_PASSWORD", "")
	MAIL_FROM_ADDRESS = GetMergedItem(merged, "MAIL_FROM_ADDRESS", "")
	MAIL_FROM_NAME = GetMergedItem(merged, "MAIL_FROM_NAME", "")

	// HELPDESK
	HELPDESK_EMAIL = GetMergedItem(merged, "HELPDESK_EMAIL", "")
	HELPDESK_PHONE = GetMergedItem(merged, "HELPDESK_PHONE", "")
	HELPDESK_WHATSAPP = GetMergedItem(merged, "HELPDESK_WHATSAPP", "")

	// SECURITY
	SECURITY_ISSUE_EMAIL = GetMergedItem(merged, "SECURITY_ISSUE_EMAIL", "")

	// CLAMAV
	CLAMAV_ENABLED = GetMergedItem(merged, "CLAMAV_ENABLED", false)
	CLAMAV_HOST = GetMergedItem(merged, "CLAMAV_HOST", "")
	CLAMAV_PORT = GetMergedItem(merged, "CLAMAV_PORT", "")

	// LLM (legacy)
	LLM_ENDPOINT = GetMergedItem(merged, "LLM_ENDPOINT", "")
	LLM_EMAIL = GetMergedItem(merged, "LLM_EMAIL", "")
	LLM_PASSWORD = GetMergedItem(merged, "LLM_PASSWORD", "")

	// RECAPTCHA
	RECAPTCHA_SECRET_KEY = GetMergedItem(merged, "RECAPTCHA_SECRET_KEY", "")

	// WEBAUTHN
	WEBAUTHN_RP_ID = GetMergedItem(merged, "WEBAUTHN_RP_ID", "")
	WEBAUTHN_RP_NAME = GetMergedItem(merged, "WEBAUTHN_RP_NAME", "")
	WEBAUTHN_RP_ORIGINS = GetMergedItem(merged, "WEBAUTHN_RP_ORIGINS", "")

	// CORS
	CORS_ALLOW_ORIGINS = GetMergedItem(merged, "CORS_ALLOW_ORIGINS", "")

	// SENTRY
	SENTRY_DSN = GetMergedItem(merged, "SENTRY_DSN", "")
	SENTRY_SAMPLE_RATE = GetMergedItem(merged, "SENTRY_SAMPLE_RATE", 1.0)

	// OTEL
	OTEL_TRACES_ENABLED = GetMergedItem(merged, "OTEL_TRACES_ENABLED", false)
	OTEL_TRACES_EXPORTER = GetMergedItem(merged, "OTEL_TRACES_EXPORTER", "otlp")
	OTEL_EXPORTER_OTLP_ENDPOINT = GetMergedItem(merged, "OTEL_EXPORTER_OTLP_ENDPOINT", "")
	OTEL_EXPORTER_ZIPKIN_ENDPOINT = GetMergedItem(merged, "OTEL_EXPORTER_ZIPKIN_ENDPOINT", "")
	OTEL_TRACES_SAMPLE_RATE = GetMergedItem(merged, "OTEL_TRACES_SAMPLE_RATE", 0.05)

	// SERVICE-SPECIFIC
	SERVICE_VERSION = GetMergedItem(merged, "SERVICE_VERSION", "")
	AUTO_MIGRATION = GetMergedItem(merged, "AUTO_MIGRATION", false)

	// SCHEDULER
	DATA_CONNECTOR_CRON_EXP = GetMergedItem(merged, "DATA_CONNECTOR_CRON_EXP", "")
	JISDOR_CRON_EXP = GetMergedItem(merged, "JISDOR_CRON_EXP", "")
	SENTRAL_CRON_EXP = GetMergedItem(merged, "SENTRAL_CRON_EXP", "")
	KURS_TENGAH_CRON_EXP = GetMergedItem(merged, "KURS_TENGAH_CRON_EXP", "")
	ASSET_CRON_EXP = GetMergedItem(merged, "ASSET_CRON_EXP", "")

	// INTEGRATION
	AMS_TOKEN = GetMergedItem(merged, "AMS_TOKEN", "")
	BI_KURS_TENGAH_URL = GetMergedItem(merged, "BI_KURS_TENGAH_URL", "")
	BI_JISDOR_URL = GetMergedItem(merged, "BI_JISDOR_URL", "")
	SAP_BASE_URL = GetMergedItem(merged, "SAP_BASE_URL", "")
	SAP_API_KEY = GetMergedItem(merged, "SAP_API_KEY", "")
	SAP_API_USER = GetMergedItem(merged, "SAP_API_USER", "")
	SAP_API_PASSWORD = GetMergedItem(merged, "SAP_API_PASSWORD", "")

	// UPLOAD
	UPLOAD_MAX_SIZE_MB = GetMergedItem(merged, "UPLOAD_MAX_SIZE_MB", int64(10))
	WS_READ_BUFFER_SIZE = GetMergedItem(merged, "WS_READ_BUFFER_SIZE", 1024)
	WS_WRITE_BUFFER_SIZE = GetMergedItem(merged, "WS_WRITE_BUFFER_SIZE", 1024)

	// KAFKA
	KAFKA_BROKER = GetMergedItem(merged, "KAFKA_BROKER", "")
	KAFKA_BROKERS = GetMergedItem(merged, "KAFKA_BROKERS", "")
	KAFKA_BROKER_ADDRESSES = GetMergedItem(merged, "KAFKA_BROKER_ADDRESSES", "")
	KAFKA_CLIENT_ID = GetMergedItem(merged, "KAFKA_CLIENT_ID", "")
	KAFKA_GROUP = GetMergedItem(merged, "KAFKA_GROUP", "")
	KAFKA_SASL_USER = GetMergedItem(merged, "KAFKA_SASL_USER", "")
	KAFKA_SASL_PASSWORD = GetMergedItem(merged, "KAFKA_SASL_PASSWORD", "")
	KAFKA_SASL_MECHANISM = GetMergedItem(merged, "KAFKA_SASL_MECHANISM", "SCRAM-SHA-512")
	KAFKA_TLS_ENABLE = GetMergedItem(merged, "KAFKA_TLS_ENABLE", false)
	KAFKA_TLS_SKIP_VERIFY = GetMergedItem(merged, "KAFKA_TLS_SKIP_VERIFY", false)
}

// GetMergedItem reads a key from a merged map of Vault secrets.
// Mirrors GetVaultItem semantics (NA handling, panic on missing without default).
func GetMergedItem[T any](merged map[string]any, key string, defaultValue ...T) T {
	env, ok := merged[key]
	if !ok || env == "" {
		return getVaultDefaultValue(key, defaultValue...)
	}

	if isNAValue(env) {
		return getVaultDefaultValue(key, defaultValue...)
	}

	return convertVaultValue[T](env, key)
}

func setConfigFromEnv() {
	BASE_URL = GetEnv("BASE_URL", "")

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
	COOKIE_DOMAIN = GetEnv("COOKIE_DOMAIN", "")
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
	WS_READ_BUFFER_SIZE = GetEnv("WS_READ_BUFFER_SIZE", 1024)
	WS_WRITE_BUFFER_SIZE = GetEnv("WS_WRITE_BUFFER_SIZE", 1024)

	// KAFKA
	KAFKA_BROKER = GetEnv("KAFKA_BROKER", "")
	KAFKA_BROKERS = GetEnv("KAFKA_BROKERS", "")
	KAFKA_BROKER_ADDRESSES = GetEnv("KAFKA_BROKER_ADDRESSES", "")
	KAFKA_CLIENT_ID = GetEnv("KAFKA_CLIENT_ID", "")
	KAFKA_GROUP = GetEnv("KAFKA_GROUP", "")
	KAFKA_SASL_USER = GetEnv("KAFKA_SASL_USER", "")
	KAFKA_SASL_PASSWORD = GetEnv("KAFKA_SASL_PASSWORD", "")
	KAFKA_SASL_MECHANISM = GetEnv("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512")
	KAFKA_TLS_ENABLE = GetEnv("KAFKA_TLS_ENABLE", false)
	KAFKA_TLS_SKIP_VERIFY = GetEnv("KAFKA_TLS_SKIP_VERIFY", false)

	// SERVICE-SPECIFIC (migrated from per-service configs/env.go)
	SERVICE_VERSION = GetEnv("SERVICE_VERSION", "")
	AUTO_MIGRATION = GetEnv("AUTO_MIGRATION", false)

	// SCHEDULER
	DATA_CONNECTOR_CRON_EXP = GetEnv("DATA_CONNECTOR_CRON_EXP", "")
	JISDOR_CRON_EXP = GetEnv("JISDOR_CRON_EXP", "")
	SENTRAL_CRON_EXP = GetEnv("SENTRAL_CRON_EXP", "")
	KURS_TENGAH_CRON_EXP = GetEnv("KURS_TENGAH_CRON_EXP", "")
	ASSET_CRON_EXP = GetEnv("ASSET_CRON_EXP", "")

	// INTEGRATION
	AMS_TOKEN = GetEnv("AMS_TOKEN", "")
	BI_KURS_TENGAH_URL = GetEnv("BI_KURS_TENGAH_URL", "")
	BI_JISDOR_URL = GetEnv("BI_JISDOR_URL", "")
	SAP_BASE_URL = GetEnv("SAP_BASE_URL", "")
	SAP_API_KEY = GetEnv("SAP_API_KEY", "")
	SAP_API_USER = GetEnv("SAP_API_USER", "")
	SAP_API_PASSWORD = GetEnv("SAP_API_PASSWORD", "")

	// CLAMAV
	CLAMAV_ENABLED = GetEnv("CLAMAV_ENABLED", false)
	CLAMAV_HOST = GetEnv("CLAMAV_HOST", "")
	CLAMAV_PORT = GetEnv("CLAMAV_PORT", "")

	// LLM
	LLM_ENDPOINT = GetEnv("LLM_ENDPOINT", "")
	LLM_EMAIL = GetEnv("LLM_EMAIL", "")
	LLM_PASSWORD = GetEnv("LLM_PASSWORD", "")

	// MAIL
	MAIL_HOST = GetEnv("MAIL_HOST", "")
	MAIL_PORT = GetEnv("MAIL_PORT", 587)
	MAIL_USERNAME = GetEnv("MAIL_USERNAME", "")
	MAIL_PASSWORD = GetEnv("MAIL_PASSWORD", "")
	MAIL_FROM_ADDRESS = GetEnv("MAIL_FROM_ADDRESS", "")
	MAIL_FROM_NAME = GetEnv("MAIL_FROM_NAME", "")

	// RECAPTCHA
	RECAPTCHA_SECRET_KEY = GetEnv("RECAPTCHA_SECRET_KEY", "")

	// WEBAUTHN
	WEBAUTHN_RP_ID = GetEnv("WEBAUTHN_RP_ID", "")
	WEBAUTHN_RP_NAME = GetEnv("WEBAUTHN_RP_NAME", "")
	WEBAUTHN_RP_ORIGINS = GetEnv("WEBAUTHN_RP_ORIGINS", "")

	// CORS
	CORS_ALLOW_ORIGINS = GetEnv("CORS_ALLOW_ORIGINS", "")

	// HELPDESK
	HELPDESK_EMAIL = GetEnv("HELPDESK_EMAIL", "")
	HELPDESK_PHONE = GetEnv("HELPDESK_PHONE", "")
	HELPDESK_WHATSAPP = GetEnv("HELPDESK_WHATSAPP", "")

	// SECURITY
	SECURITY_ISSUE_EMAIL = GetEnv("SECURITY_ISSUE_EMAIL", "")

	// SENTRY
	SENTRY_DSN = GetEnv("SENTRY_DSN", "")
	SENTRY_SAMPLE_RATE = GetEnv("SENTRY_SAMPLE_RATE", 1.0)

	// OTEL
	OTEL_TRACES_ENABLED = GetEnv("OTEL_TRACES_ENABLED", false)
	OTEL_TRACES_EXPORTER = GetEnv("OTEL_TRACES_EXPORTER", "otlp")
	OTEL_EXPORTER_OTLP_ENDPOINT = GetEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	OTEL_EXPORTER_ZIPKIN_ENDPOINT = GetEnv("OTEL_EXPORTER_ZIPKIN_ENDPOINT", "")
	OTEL_TRACES_SAMPLE_RATE = GetEnv("OTEL_TRACES_SAMPLE_RATE", 0.05)

	validateSecretKeys()
}

func validateSecretKeys() {
	const minJWTKeyLen = 32
	const minAESKeyLen = 16
	const minGatewaySecretLen = 32

	if len(JWT_SECRET_KEY) < minJWTKeyLen {
		panic(fmt.Sprintf("JWT_SECRET_KEY must be at least %d characters long", minJWTKeyLen))
	}
	if len(CRYPTO_ENCRYPTION_KEY) < minAESKeyLen {
		panic(fmt.Sprintf("CRYPTO_ENCRYPTION_KEY must be at least %d characters long", minAESKeyLen))
	}
	if PAYLOAD_ENCRYPTION_KEY != "" && len(PAYLOAD_ENCRYPTION_KEY) < minAESKeyLen {
		panic(fmt.Sprintf("PAYLOAD_ENCRYPTION_KEY must be at least %d characters long", minAESKeyLen))
	}
	if TRUST_GATEWAY && len(GATEWAY_SHARED_SECRET) < minGatewaySecretLen {
		panic(fmt.Sprintf("GATEWAY_SHARED_SECRET must be at least %d characters long when TRUST_GATEWAY is enabled", minGatewaySecretLen))
	}
}

func GetVaultItem[T any](vaultData *vault.Response[schema.KvV2ReadResponse], key string, defaultValue ...T) T {
	env, ok := vaultData.Data.Data[key]
	if !ok || env == "" {
		return getVaultDefaultValue(key, defaultValue...)
	}

	if isNAValue(env) {
		return getVaultDefaultValue(key, defaultValue...)
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
	case int32:
		return any(int32(convertToInt(env, key))).(T)
	case int64:
		return any(int64(convertToInt(env, key))).(T)
	case float32:
		return any(float32(convertToFloat(env, key))).(T)
	case float64:
		return any(convertToFloat(env, key)).(T)
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

func convertToFloat(env any, key string) float64 {
	var v float64
	var err error

	if num, ok := env.(json.Number); ok {
		v, err = num.Float64()
	} else if str, ok := env.(string); ok {
		v, err = strconv.ParseFloat(str, 64)
	} else {
		panic("env " + key + " is not number or string")
	}

	if err != nil {
		panic("failed get env item " + key + " with error: " + err.Error())
	}

	return v
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
