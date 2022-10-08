package oauth2_infra

import (
	"context"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"net/http"
	"shpboris/keycloak-integration/auth-code-client/common"
	"shpboris/keycloak-integration/auth-code-client/session/model"
	session "shpboris/keycloak-integration/auth-code-client/session/service"
	"time"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	token, ok := fetchToken(w, r)
	if !ok {
		return
	}
	sessionId := createSession(token)
	ck := createCookie(sessionId)
	http.SetCookie(w, &ck)
	http.Redirect(w, r, "/", http.StatusFound)
}

func fetchToken(w http.ResponseWriter, r *http.Request) (*oauth2.Token, bool) {
	err := r.ParseForm()
	if common.HandlePossibleError(w, err) {
		return nil, false
	}
	code := r.Form.Get("code")
	if code == "" {
		common.HandleSpecificError(w, "Code not found", http.StatusBadRequest)
		return nil, false
	}
	config := GetOauth2ConfigProvider().GetConfig()
	token, err := config.Exchange(context.Background(), code)
	if common.HandlePossibleError(w, err) {
		return nil, false
	}
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
	expires := time.Now().Add(10 * time.Hour)
	ck := http.Cookie{
		Name:     "SESSION_ID",
		Domain:   "localhost",
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
	}
	ck.Value = id
	return ck
}
