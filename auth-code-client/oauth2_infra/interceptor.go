package oauth2_infra

import (
	"context"
	"fmt"
	"github.com/Nerzal/gocloak/v11"
	"github.com/shpboris/logger"
	"net/http"
	"os"
	session "shpboris/keycloak-integration/auth-code-client/session/service"
	"strings"
	"time"
)

func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.RequestURI, "/oauth") {
			ctx := context.Background()
			ck, err := r.Cookie("SESSION_ID")
			if err != nil || ck == nil || !validateOrRefreshToken(ctx, ck.Value) {
				config := NewOauth2ConfigProvider().GetConfig()
				u := config.AuthCodeURL("xyz")
				http.Redirect(w, r, u, http.StatusFound)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func validateOrRefreshToken(ctx context.Context, id string) bool {
	sessionStoreService := session.NewSessionStoreService()
	if sessionStoreService.GetSession(id) == nil {
		return false
	}
	token := sessionStoreService.GetSession(id).Token
	if token.Expiry.Before(time.Now()) {
		config := NewOauth2ConfigProvider().GetConfig()
		keyCloakURL := os.Getenv("KEYCLOAK_URL")
		realm := os.Getenv("REALM")
		client := gocloak.NewClient(keyCloakURL)
		jwt, err := client.RefreshToken(ctx, token.RefreshToken, config.ClientID, config.ClientSecret, realm)
		if err != nil {
			return false
		}
		token.AccessToken = jwt.AccessToken
		token.RefreshToken = jwt.RefreshToken
		token.Expiry = time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second)
	}

	msg := fmt.Sprintf("Found token: %s", token.AccessToken)
	logger.Log.Info(msg)
	return true
}
