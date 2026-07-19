package configs

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetCsrfToken(c *gin.Context) {
	csrfToken, err := GenerateToken(128)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Could not generate CSRF token"})
		return
	}

	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(COOKIE_PREFIX+"_"+"csrf_token",
		csrfToken,
		3600,
		COOKIE_PATH,
		COOKIE_DOMAIN,
		COOKIE_SECURE,
		COOKIE_HTTP_ONLY,
	)

	c.Header("X-CSRF-Token", csrfToken)
}
