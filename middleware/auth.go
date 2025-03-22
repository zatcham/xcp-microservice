package middleware

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

var (
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
)

// SetOIDC sets the OIDC provider and verifier (called from main)
func SetOIDC(p *oidc.Provider, v *oidc.IDTokenVerifier) {
	provider = p
	verifier = v
}

// AuthMiddleware validates JWT tokens from Keycloak
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if OIDC is initialised
		if provider == nil || verifier == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "OIDC not initialized"})
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		// Extract Bearer token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			return
		}

		// Validate token
		idToken, err := verifier.Verify(context.Background(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Store claims in context for handlers
		c.Set("claims", idToken.Claims)
		c.Next()
	}
}
