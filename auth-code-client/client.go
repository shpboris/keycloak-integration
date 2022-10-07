package main

import (
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/shpboris/logger"
	"log"
	"net/http"
	"os"
	"shpboris/keycloak-integration/auth-code-client/oauth2_infra"
)

func main() {
	err := godotenv.Load("./auth-code-client/.env")
	if err != nil {
		logger.Log.Error(err.Error())
		return
	}
	oauth2_infra.InitOauth2ConfigProvider()
	r := mux.NewRouter()
	r.HandleFunc("/", homePage)
	r.HandleFunc("/nested", nestedPage)
	r.HandleFunc("/oauth2", oauth2_infra.Authorize)
	r.Use(oauth2_infra.HeaderMiddleware)
	log.Println("Client is running at 9094 port.")
	log.Fatal(http.ListenAndServe(":9094", r))
}

func homePage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, "./auth-code-client/static/home.html")
}

func nestedPage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, "./auth-code-client/static/nested.html")
}

func loadPage(w http.ResponseWriter, r *http.Request, filePath string) {
	b, err := os.ReadFile(filePath)
	if handlePossibleError(err, w) {
		return
	}
	w.Header().Set("Content-type", "text/html")
	_, err = w.Write(b)
	handlePossibleError(err, w)
}

func handlePossibleError(err error, w http.ResponseWriter) bool {
	if err != nil {
		logger.Log.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}
	return false
}
