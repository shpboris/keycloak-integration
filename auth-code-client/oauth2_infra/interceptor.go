package oauth2_infra

import (
	"context"
	"fmt"
	"github.com/shpboris/logger"
	"net/http"
	"os"
	"shpboris/auth-code-client/common/constants"
	"strings"
)

func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Info("Started interceptor flow")
		ctx := r.Context()
		if !isOpenURI(r.RequestURI) {
			ck, _ := r.Cookie(constants.SessionIdCookieName)
			token, ok := ValidateOrRefreshToken(ctx, ck)
			if ok {
				logger.Log.Info("Setting context params")
				ctx = context.WithValue(ctx, constants.TokenNameKey, token.AccessToken)
				ctx = context.WithValue(ctx, constants.RealmNameKey, os.Getenv(constants.RealmEnvKey))
				r = r.WithContext(ctx)
			} else {
				logger.Log.Info("Redirecting to KeyCloak")
				config := GetOauth2ConfigProvider().GetConfig()
				u := config.AuthCodeURL("")
				http.Redirect(w, r, u, http.StatusFound)
				return
			}
		}
		logger.Log.Info("Completed interceptor flow")
		next.ServeHTTP(w, r)
	})
}

func isOpenURI(reqURI string) bool {
	logger.Log.Info(fmt.Sprintf("Checking URI %s", reqURI))
	res := strings.Contains(reqURI, "/oauth") || strings.Contains(reqURI, "/logout")
	if res {
		logger.Log.Info("URI is open, ignoring token validation")
	}
	return res
}
