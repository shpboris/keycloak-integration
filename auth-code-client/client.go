package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/shpboris/logger"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	idToTokenMap = make(map[string]*oauth2.Token)
	config       = oauth2.Config{
		ClientID:     "keycloak-integration-app",
		ClientSecret: "BnpvHny0VkN8k1DaTKykr7KzdYJCpKyX",
		//Scopes:       []string{"all"},
		RedirectURL: "http://localhost:9094/oauth2",
		// This points to our Authorization Server
		// if our Client ID and Client Secret are valid
		// it will attempt to authorize our user
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://keycloak-http:9999/auth/realms/mytest1/protocol/openid-connect/auth",
			TokenURL: "http://keycloak-http:9999/auth/realms/mytest1/protocol/openid-connect/token",
		},
	}
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homePage)
	r.HandleFunc("/nested", nestedPage)
	r.HandleFunc("/oauth2", Authorize)
	r.Use(HeaderMiddleware)
	log.Println("Client is running at 9094 port.")
	log.Fatal(http.ListenAndServe(":9094", r))
}

func homePage(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile("./static/home.html")
	if handlePossibleError(err, w) {
		return
	}
	w.Header().Set("Content-type", "text/html")
	_, err = w.Write(b)
	handlePossibleError(err, w)
}

func nestedPage(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile("./static/nested.html")
	if handlePossibleError(err, w) {
		return
	}
	w.Header().Set("Content-type", "text/html")
	_, err = w.Write(b)
	handlePossibleError(err, w)
}

func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.RequestURI, "/oauth") {
			ck, _ := r.Cookie("SESSION_ID")
			if ck == nil || !validateOrRefreshToken(ck.Value) {
				u := config.AuthCodeURL("xyz")
				http.Redirect(w, r, u, http.StatusFound)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Authorize
func Authorize(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
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

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id := uuid.New().String()
	idToTokenMap[id] = token

	expires := time.Now().AddDate(0, 0, 1)
	ck := http.Cookie{
		Name:    "SESSION_ID",
		Domain:  "localhost",
		Path:    "/",
		Expires: expires,
	}
	ck.Value = id
	http.SetCookie(w, &ck)

	http.Redirect(w, r, "/", http.StatusFound)
}

func validateOrRefreshToken(id string) bool {
	token := idToTokenMap[id]
	msg := fmt.Sprintf("Found token: %s", token.AccessToken)
	logger.Log.Info(msg)
	return true
}

func handlePossibleError(err error, w http.ResponseWriter) bool {
	if err != nil {
		logger.Log.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}
	return false
}
