package oauth2_infra

import (
	"context"
	"github.com/shpboris/logger"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"shpboris/auth-code-client/common/constants"
	"shpboris/auth-code-client/common/utils"
	session "shpboris/auth-code-client/session/service"
	"time"
)

func ValidateOrRefreshToken(ctx context.Context, ck *http.Cookie) (*oauth2.Token, bool) {
	logger.Log.Info("Started validateOrRefreshToken")
	if !utils.IsCookieNotEmpty(ck) {
		logger.Log.Warn("Cookie is empty")
		return nil, false
	}
	sessionStoreService := session.GetSessionStoreService()
	if sessionStoreService.GetSession(ck.Value) == nil {
		logger.Log.Warn("Session does not exist")
		return nil, false
	}
	token := sessionStoreService.GetSession(ck.Value).Token
	if token.Expiry.Before(time.Now()) {
		config := GetOauth2ConfigProvider().GetConfig()
		realm := os.Getenv(constants.RealmEnvKey)
		client := utils.GetKeyCloakClient()
		logger.Log.Warn("Token is expired, performing refresh")
		jwt, err := client.RefreshToken(ctx, token.RefreshToken, config.ClientID, config.ClientSecret, realm)
		if err != nil {
			logger.Log.Error("Refresh token failed", err)
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
