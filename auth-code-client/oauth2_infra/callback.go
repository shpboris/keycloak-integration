package oauth2_infra

import (
	"context"
	"github.com/google/uuid"
	"github.com/shpboris/logger"
	"golang.org/x/oauth2"
	"net/http"
	"shpboris/auth-code-client/common/constants"
	"shpboris/auth-code-client/common/utils"
	"shpboris/auth-code-client/session/model"
	session "shpboris/auth-code-client/session/service"
	"time"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started Authorize flow")
	token, ok := fetchToken(w, r)
	if !ok {
		return
	}
	sessionId := createSession(token)
	ck := createCookie(sessionId)
	http.SetCookie(w, &ck)
	logger.Log.Info("Completed Authorize flow")
	http.Redirect(w, r, constants.HomePageURL, http.StatusFound)
}

func fetchToken(w http.ResponseWriter, r *http.Request) (*oauth2.Token, bool) {
	logger.Log.Info("Started fetchToken")
	err := r.ParseForm()
	if utils.HandlePossibleError(w, err) {
		return nil, false
	}
	code := r.Form.Get("code")
	if code == "" {
		utils.HandleSpecificError(w, "Code not found", http.StatusBadRequest)
		return nil, false
	}
	config := GetOauth2ConfigProvider().GetConfig()
	token, err := config.Exchange(context.Background(), code)
	if utils.HandlePossibleError(w, err) {
		return nil, false
	}
	logger.Log.Info("Completed fetchToken")
	return token, true
}

func createSession(token *oauth2.Token) string {
	sessionStoreService := session.GetSessionStoreService()
	sessionId := uuid.New().String()
	newSession := model.Session{Token: token}
	sessionStoreService.StoreSession(sessionId, &newSession)
	return sessionId
}

func createCookie(id string) http.Cookie {
	expires := time.Now().Add(constants.SessionIdCookieDuration * time.Hour)
	ck := http.Cookie{
		Name:     constants.SessionIdCookieName,
		Domain:   "localhost",
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
	}
	ck.Value = id
	return ck
}
