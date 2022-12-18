package oauth2_infra

import (
	"context"
	"fmt"
	"github.com/Nerzal/gocloak/v11"
	"github.com/shpboris/logger"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"shpboris/security-service/common/constants"
	session "shpboris/security-service/session/service"
	"strings"
	"time"
)

func Introspect(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started Introspect flow")
	ctx := context.Background()
	sessionIdHeaderVal := r.Header.Get(constants.SessionIdCookieName)
	logger.Log.Info(fmt.Sprintf("Received session id: %s", sessionIdHeaderVal))
	var token *oauth2.Token = nil
	ok := false
	if len(strings.TrimSpace(sessionIdHeaderVal)) != 0 {
		token, ok = validateOrRefreshToken(ctx, sessionIdHeaderVal)
	}
	if !ok {
		config := GetOauth2ConfigProvider().GetConfig()
		u := config.AuthCodeURL("")
		logger.Log.Info(fmt.Sprintf("Returning 401, redirect URL is: %s", u))
		w.Header().Set("redirect_url", u)
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		logger.Log.Info(fmt.Sprintf("Returning 200"))
		w.Header().Set("token", token.AccessToken)
		w.WriteHeader(http.StatusOK)
	}
	logger.Log.Info("Completed Introspect flow")
}

func validateOrRefreshToken(ctx context.Context, id string) (*oauth2.Token, bool) {
	logger.Log.Info("Started validateOrRefreshToken")
	sessionStoreService := session.GetSessionStoreService()
	if sessionStoreService.GetSession(id) == nil {
		logger.Log.Info("Session does not exist")
		return nil, false
	}
	token := sessionStoreService.GetSession(id).Token
	if token.Expiry.Before(time.Now()) {
		config := GetOauth2ConfigProvider().GetConfig()
		realm := os.Getenv(constants.RealmEnvKey)
		client := getKeyCloakClient()
		logger.Log.Warn("Token is expired, performing refresh")
		jwt, err := client.RefreshToken(ctx, token.RefreshToken, config.ClientID, config.ClientSecret, realm)
		if err != nil {
			logger.Log.Warn("Refresh token failed")
			logger.Log.Error(err)
			return nil, false
		}
		logger.Log.Info("Refreshed token")
		token.AccessToken = jwt.AccessToken
		token.RefreshToken = jwt.RefreshToken
		token.Expiry = time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second)
	}
	logger.Log.Info("Token is good")
	logger.Log.Info("Completed validateOrRefreshToken")
	return token, true
}

func getKeyCloakClient() gocloak.GoCloak {
	keyCloakURL := os.Getenv(constants.KeycloakURLEnvkey)
	return gocloak.NewClient(keyCloakURL)
}
