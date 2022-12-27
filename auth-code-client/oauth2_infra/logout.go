package oauth2_infra

import (
	"github.com/shpboris/logger"
	"net/http"
	"os"
	"shpboris/auth-code-client/common/constants"
	"shpboris/auth-code-client/common/utils"
	session "shpboris/auth-code-client/session/service"
	"time"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started Logout flow")
	ck, _ := r.Cookie(constants.SessionIdCookieName)
	token, ok := ValidateOrRefreshToken(r.Context(), ck)
	if ok {
		realm := os.Getenv(constants.RealmEnvKey)
		client := utils.GetKeyCloakClient()
		_, claims, _ := client.DecodeAccessToken(r.Context(), token.AccessToken, realm)
		userId := (*claims)["sub"]
		err := client.LogoutAllSessions(r.Context(), token.AccessToken, realm, userId.(string))
		if err != nil {
			logger.Log.Error("Failed to logout user sessions", err)
		}
	}
	if utils.IsCookieNotEmpty(ck) {
		session.GetSessionStoreService().DeleteSession(ck.Value)
		ck.Expires = time.Now().Add(-constants.SessionIdCookieDuration * time.Hour)
		http.SetCookie(w, ck)
	}
	logger.Log.Info("Completed Logout flow")
	http.Redirect(w, r, constants.HomePageURL, http.StatusFound)
}
