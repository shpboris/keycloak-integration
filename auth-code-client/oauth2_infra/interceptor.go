package oauth2_infra

import (
	"context"
	"fmt"
	"github.com/Nerzal/gocloak/v11"
	"github.com/shpboris/logger"
	"net/http"
	"os"
	"shpboris/keycloak-integration/auth-code-client/common/constants"
	session "shpboris/keycloak-integration/auth-code-client/session/service"
	"strings"
	"time"
)

func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Info("Started interceptor flow")
		if !isOpenURI(r.RequestURI) {
			ctx := context.Background()
			ck, err := r.Cookie(constants.SessionIdCookieName)
			if err != nil || ck == nil || !validateOrRefreshToken(ctx, ck.Value) {
				logger.Log.Info("Redirecting to KeyCloak")
				config := GetOauth2ConfigProvider().GetConfig()
				u := config.AuthCodeURL("")
				http.Redirect(w, r, u, http.StatusFound)
			}
		}
		logger.Log.Info("Completed interceptor flow")
		next.ServeHTTP(w, r)
	})
}

func validateOrRefreshToken(ctx context.Context, id string) bool {
	logger.Log.Info("Started validateOrRefreshToken")
	sessionStoreService := session.GetSessionStoreService()
	if sessionStoreService.GetSession(id) == nil {
		logger.Log.Info("Session does not exist")
		return false
	}
	token := sessionStoreService.GetSession(id).Token
	if token.Expiry.Before(time.Now()) {
		config := GetOauth2ConfigProvider().GetConfig()
		realm := os.Getenv(constants.RealmEnvKey)
		client := getKeyCloakClient()
		jwt, err := client.RefreshToken(ctx, token.RefreshToken, config.ClientID, config.ClientSecret, realm)
		if err != nil {
			logger.Log.Warn("Refresh token failed")
			return false
		}
		logger.Log.Info("Refreshed token")
		token.AccessToken = jwt.AccessToken
		token.RefreshToken = jwt.RefreshToken
		token.Expiry = time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second)
	}
	logger.Log.Info("Token is good")
	logger.Log.Info("Completed validateOrRefreshToken")
	return true
}

func getKeyCloakClient() gocloak.GoCloak {
	keyCloakURL := os.Getenv(constants.KeycloakURLEnvkey)
	return gocloak.NewClient(keyCloakURL)
}

func isOpenURI(reqURI string) bool {
	logger.Log.Info(fmt.Sprintf("Checking URI %s", reqURI))
	res := strings.Contains(reqURI, "/oauth")
	if res {
		logger.Log.Info("URI is open, ignoring token validation")
	}
	return res
}
