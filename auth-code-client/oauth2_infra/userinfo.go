package oauth2_infra

import (
	"context"
	"github.com/Nerzal/gocloak/v11"
	"github.com/shpboris/logger"
	"shpboris/auth-code-client/common/utils"
)

func GetUserInfo(ctx context.Context) (*gocloak.UserInfo, error) {
	logger.Log.Info("Started GetUserInfo")
	token, realm := utils.GetContextParams(ctx)
	client := utils.GetKeyCloakClient()
	userInfo, err := client.GetUserInfo(ctx, token, realm)
	if err != nil {
		logger.Log.Error("Failed to fetch user info", err)
		return nil, err
	}
	logger.Log.Info("Completed GetUserInfo")
	return userInfo, nil
}
