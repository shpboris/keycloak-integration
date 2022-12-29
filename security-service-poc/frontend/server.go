package main

import (
	_ "embed"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/shpboris/logger"
	"log"
	"net/http"
	"shpboris/frontend/client"
	"shpboris/frontend/common/constants"
	"shpboris/frontend/common/utils"
	"strings"
)

//go:embed static/home.html
var home_resource string

//go:embed static/nested.html
var nested_resource string

func main() {
	r := mux.NewRouter()
	r.HandleFunc(constants.HomePagePath, homePage)
	r.HandleFunc(constants.NestedPagePath, nestedPage)
	logger.Log.Info("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func homePage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.HomePagePath)
}

func nestedPage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.NestedPagePath)
}

func loadPage(w http.ResponseWriter, r *http.Request, path string) {
	logger.Log.Info("Started loadPage")
	logger.Log.Info(fmt.Sprintf("Handling request: %s", r.RequestURI))
	accessToken := r.Header.Get(constants.TokenHeaderName)
	if len(strings.TrimSpace(accessToken)) == 0 {
		utils.HandleSpecificError(w, "Token is empty", 400)
		return
	}
	logger.Log.Info(fmt.Sprintf("Received token : %s", accessToken))
	var resource string
	if path == constants.HomePagePath {
		resource = home_resource
	} else {
		resource = nested_resource
	}
	userInfo, err := client.GetUserInfo(accessToken)
	if err != nil {
		logger.Log.Error("Failed to get user info", err)
	}
	if userInfo != nil {
		resource = strings.ReplaceAll(resource, "$user$", *userInfo.PreferredUsername)
	}
	w.Header().Set("Content-type", "text/html")
	_, err = w.Write([]byte(resource))
	utils.HandlePossibleError(w, err)
	logger.Log.Info("Completed loadPage")
}
