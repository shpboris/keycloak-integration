package oauth2_infra

import (
	"context"
	"github.com/google/uuid"
	"net/http"
	"shpboris/keycloak-integration/auth-code-client/session/model"
	session "shpboris/keycloak-integration/auth-code-client/session/service"
	"time"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	state := r.Form.Get("state")
	if state != "xyz" {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	config := NewOauth2ConfigProvider().GetConfig()
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionStoreService := session.NewSessionStoreService()
	id := uuid.New().String()
	newSession := model.Session{Token: token}
	sessionStoreService.StoreSession(id, &newSession)

	expires := time.Now().AddDate(0, 0, 1)
	ck := http.Cookie{
		Name:     "SESSION_ID",
		Domain:   "localhost",
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
	}
	ck.Value = id
	http.SetCookie(w, &ck)

	http.Redirect(w, r, "/", http.StatusFound)
}
