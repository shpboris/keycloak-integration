package oauth2_infra

import (
	"fmt"
	"github.com/shpboris/logger"
	"net/http"
	"os"
	"shpboris/security-service/common/constants"
	"shpboris/security-service/common/utils"
	session "shpboris/security-service/session/service"
	"strings"
	"time"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started Logout flow")
	sessionIdCookie, _ := r.Cookie(constants.SessionIdCookieName)
	logoutUserSessions(r, sessionIdCookie)
	deleteFromSessionStore(sessionIdCookie)
	invalidateCookies(w, r)
	logger.Log.Info("Completed Logout flow")
	http.Redirect(w, r, constants.HomePageURL, http.StatusFound)
}

func logoutUserSessions(r *http.Request, sessionIdCookie *http.Cookie) {
	if IsCookieNotEmpty(sessionIdCookie) {
		logger.Log.Error("Logging out user sessions")
		token, ok := ValidateOrRefreshToken(r.Context(), sessionIdCookie.Value)
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
	}
}

func deleteFromSessionStore(sessionIdCookie *http.Cookie) {
	logger.Log.Info("Started deleteFromSessionStore")
	if IsCookieNotEmpty(sessionIdCookie) {
		session.GetSessionStoreService().DeleteSession(sessionIdCookie.Value)
	}
	logger.Log.Info("Completed deleteFromSessionStore")
}

func invalidateCookies(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started invalidateCookies")
	for _, currCookie := range r.Cookies() {
		logger.Log.Info(fmt.Sprintf("Invalidating cookie: %s", currCookie.Name))
		currCookie.Expires = time.Now().Add(-constants.SessionIdCookieDuration * time.Hour)
		http.SetCookie(w, currCookie)
	}
	logger.Log.Info("Completed invalidateCookies")
}

func IsCookieNotEmpty(ck *http.Cookie) bool {
	return ck != nil && len(strings.TrimSpace(ck.Value)) != 0
}
