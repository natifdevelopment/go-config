package configs

import (
	"strings"
)

type CorsConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials []string
}

func LoadCorsConfig() CorsConfig {
	originsStr := GetEnv("CORS_ALLOW_ORIGINS", "")
	allowOrigins := strings.Split(originsStr, ",")
	for i, o := range allowOrigins {
		allowOrigins[i] = strings.TrimSpace(o)
	}

	return CorsConfig{
		AllowOrigins:     allowOrigins,
		AllowMethods:     []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization", "X-API-Key", "X-CSRF-Token", "X-Signature", "X-Timestamp"},
		AllowCredentials: []string{"true"},
		ExposeHeaders:    []string{"X-CSRF-Token"},
	}
}
