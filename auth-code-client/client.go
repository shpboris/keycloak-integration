package main

import (
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/shpboris/logger"
	"log"
	"net/http"
	"os"
	"shpboris/keycloak-integration/auth-code-client/common/constants"
	"shpboris/keycloak-integration/auth-code-client/common/utils"
	"shpboris/keycloak-integration/auth-code-client/oauth2_infra"
)

func main() {
	err := initAuth()
	if err != nil {
		return
	}
	r := mux.NewRouter()
	r.HandleFunc("/", homePage)
	r.HandleFunc("/nested", nestedPage)
	r.HandleFunc("/oauth2", oauth2_infra.Authorize)
	r.Use(oauth2_infra.HeaderMiddleware)
	log.Println("Client is running at 9094 port.")
	log.Fatal(http.ListenAndServe(":9094", r))
}

func homePage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.HomePageFilePath)
}

func nestedPage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.NestedPageFilePath)
}

func loadPage(w http.ResponseWriter, r *http.Request, filePath string) {
	b, err := os.ReadFile(filePath)
	if utils.HandlePossibleError(w, err) {
		return
	}
	w.Header().Set("Content-type", "text/html")
	_, err = w.Write(b)
	utils.HandlePossibleError(w, err)
}

func initAuth() error {
	err := godotenv.Load(constants.EnvVarsFilePath)
	if err != nil {
		logger.Log.Error(err.Error())
		return err
	}
	oauth2_infra.GetOauth2ConfigProvider().Init()
	return nil
}
