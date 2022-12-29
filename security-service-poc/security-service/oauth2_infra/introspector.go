package oauth2_infra

import (
	"context"
	"fmt"
	"github.com/shpboris/logger"
	"net/http"
	"shpboris/security-service/common/constants"
)

func Introspect(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started Introspect flow")
	ctx := context.Background()
	sessionIdHeaderVal := r.Header.Get(constants.SessionIdCookieName)
	logger.Log.Info(fmt.Sprintf("Received session id: %s", sessionIdHeaderVal))
	token, ok := ValidateOrRefreshToken(ctx, sessionIdHeaderVal)
	if ok {
		logger.Log.Info(fmt.Sprintf("Returning 200"))
		w.Header().Set(constants.TokenHeaderName, token.AccessToken)
		w.WriteHeader(http.StatusOK)
	} else {
		config := GetOauth2ConfigProvider().GetConfig()
		u := config.AuthCodeURL("")
		logger.Log.Info(fmt.Sprintf("Returning 401, redirect URL is: %s", u))
		w.Header().Set("redirect_url", u)
		w.WriteHeader(http.StatusUnauthorized)
	}
	logger.Log.Info("Completed Introspect flow")
}
