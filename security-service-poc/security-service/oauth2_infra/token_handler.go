package oauth2_infra

import (
	"context"
	"github.com/shpboris/logger"
	"golang.org/x/oauth2"
	"os"
	"shpboris/security-service/common/constants"
	"shpboris/security-service/common/utils"
	session "shpboris/security-service/session/service"
	"strings"
	"time"
)

func ValidateOrRefreshToken(ctx context.Context, cookieId string) (*oauth2.Token, bool) {
	logger.Log.Info("Started ValidateOrRefreshToken")
	if len(strings.TrimSpace(cookieId)) == 0 {
		logger.Log.Warn("Cookie ID is missing")
		return nil, false
	}
	sessionStoreService := session.GetSessionStoreService()
	if sessionStoreService.GetSession(cookieId) == nil {
		logger.Log.Warn("Session does not exist")
		return nil, false
	}
	token := sessionStoreService.GetSession(cookieId).Token
	if token.Expiry.Before(time.Now()) {
		config := GetOauth2ConfigProvider().GetConfig()
		realm := os.Getenv(constants.RealmEnvKey)
		client := utils.GetKeyCloakClient()
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
	logger.Log.Info("Completed ValidateOrRefreshToken")
	return token, true
}
