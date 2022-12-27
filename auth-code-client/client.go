package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/shpboris/logger"
	"log"
	"net/http"
	"os"
	"shpboris/auth-code-client/common/constants"
	"shpboris/auth-code-client/common/utils"
	"shpboris/auth-code-client/oauth2_infra"
	"strings"
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
	r.HandleFunc("/logout", oauth2_infra.Logout)
	r.HandleFunc("/user-info", userInfo)
	r.Use(oauth2_infra.HeaderMiddleware)
	logger.Log.Info("Client is running on port 9094")
	log.Fatal(http.ListenAndServe(":9094", r))
}

func homePage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.HomePageFilePath)
}

func nestedPage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.NestedPageFilePath)
}

func userInfo(w http.ResponseWriter, r *http.Request) {
	userInfo, err := oauth2_infra.GetUserInfo(r.Context())
	if utils.HandlePossibleError(w, err) {
		return
	}
	err = json.NewEncoder(w).Encode(userInfo)
	utils.HandlePossibleError(w, err)
}

func loadPage(w http.ResponseWriter, r *http.Request, filePath string) {
	b, err := os.ReadFile(filePath)
	if utils.HandlePossibleError(w, err) {
		return
	}
	str := string(b)
	userInfo, _ := oauth2_infra.GetUserInfo(r.Context())
	if userInfo != nil {
		str = strings.ReplaceAll(str, "$user$", *userInfo.PreferredUsername)
	}
	w.Header().Set("Content-type", "text/html")
	_, err = w.Write([]byte(str))
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
